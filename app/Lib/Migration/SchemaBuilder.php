<?php

App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('SchemaTableBuilder', 'Migration');

/**
 * The flavour-agnostic schema DSL a migration is written against.
 *
 * A migration's up() receives one of these and declares what it wants:
 *
 *     $schema->table('event_templates')
 *         ->addColumn('exposed', 'boolean', array(
 *             'null' => false, 'default' => 0, 'after' => 'misp_default'
 *         ))
 *         ->addIndex('exposed');
 *
 * It **accumulates, and emits - it never executes.** toSql() hands back an array
 * of statements and MigrationRunner decides what to do with them. That split is
 * what makes `migrationApply --dry-run` able to print a migration's MySQL *and*
 * PostgreSQL rendering without a PostgreSQL connection anywhere in sight: the
 * operations are stored as data and rendered on demand, so the same builder can
 * be handed a second grammar.
 *
 * Order is declaration order, across the whole builder. A migration that adds a
 * column, creates a table and then indexes the column gets exactly that
 * sequence, because SchemaTableBuilder pushes its operations back into this
 * object as they are called rather than batching them per table.
 *
 * ## The escape hatch
 *
 * rawSql() exists because the alternative is worse. The first irreducible case -
 * a FULLTEXT index, an enum, a statement gated on a MySQL version - would
 * otherwise send the author back to hand-written SQL and the DSL would be
 * abandoned within a release. So it is a first-class operation:
 *
 *     $schema->rawSql(array(
 *         'mysql' => "ALTER TABLE `attributes` ADD FULLTEXT INDEX `value_ft` (`value1`);",
 *         'pgsql' => "CREATE INDEX idx_attributes_value_ft ON attributes USING gin(to_tsvector('simple', value1));",
 *     ));
 *
 * A rawSql() missing the flavour being rendered is a hard error, not a skip. A
 * migration that quietly does nothing on one engine leaves that engine's schema
 * silently behind the code that expects it - the same failure the version
 * counter used to produce, in a new costume.
 *
 * @see SchemaTableBuilder
 * @see AbstractGrammar
 */
class SchemaBuilder
{
    /**
     * The operations a grammar knows how to render. addOperation() is public so
     * that SchemaTableBuilder can push through it, which means a typo would
     * otherwise reach call_user_func_array and either invoke some unrelated
     * grammar method or fatal at render time - well after the mistake was made.
     *
     * @var array
     */
    private static $renderable = array(
        'createTable',
        'dropTable',
        'renameTable',
        'addColumn',
        'changeColumn',
        'renameColumn',
        'dropColumn',
        'addIndex',
        'dropIndex',
        'dropPrimaryKey',
        'rawSql',
    );

    /**
     * @var AbstractGrammar
     */
    private $grammar;

    /**
     * Declared operations, in order, as array('operation' => ..., 'arguments' => ...).
     *
     * @var array
     */
    private $operations = array();

    public function __construct(AbstractGrammar $grammar)
    {
        $this->grammar = $grammar;
    }

    /**
     * @param DboSource $db
     * @return SchemaBuilder
     */
    public static function forDataSource(DboSource $db)
    {
        return new self(AbstractGrammar::forDataSource($db));
    }

    /**
     * @return AbstractGrammar
     */
    public function getGrammar()
    {
        return $this->grammar;
    }

    // ---------------------------------------------------------- table-scoped

    /**
     * @param string $table
     * @return SchemaTableBuilder
     */
    public function table($table)
    {
        return new SchemaTableBuilder($this, $table);
    }

    // --------------------------------------------------------- schema-scoped

    /**
     * @param string $table
     * @param array $columns name => spec. A spec is an array with at least a
     *   'type', or the bare type as a string.
     * @param array $options 'indexes' => name => index options, plus any table
     *   parameters the engine understands ('engine', 'charset', 'collate').
     * @return $this
     */
    public function createTable($table, array $columns, array $options = array())
    {
        return $this->addOperation('createTable', array($table, $columns, $options));
    }

    /**
     * @param string $table
     * @return $this
     */
    public function dropTable($table)
    {
        return $this->addOperation('dropTable', array($table));
    }

    /**
     * @param string $from
     * @param string $to
     * @return $this
     */
    public function renameTable($from, $to)
    {
        return $this->addOperation('renameTable', array($from, $to));
    }

    /**
     * Hand-written SQL, one entry per flavour.
     *
     * @param array $byFlavour Keyed by AbstractGrammar::FLAVOUR_*. A value may be
     *   a single statement or an array of them.
     * @return $this
     * @throws InvalidArgumentException On an empty map or an unknown flavour key.
     */
    public function rawSql(array $byFlavour)
    {
        if (empty($byFlavour)) {
            throw new InvalidArgumentException('rawSql() needs at least one flavour.');
        }
        $known = array(AbstractGrammar::FLAVOUR_MYSQL, AbstractGrammar::FLAVOUR_PGSQL);
        foreach (array_keys($byFlavour) as $flavour) {
            if (!in_array($flavour, $known, true)) {
                throw new InvalidArgumentException(sprintf(
                    'rawSql(): unknown flavour "%s". Known flavours are: %s.',
                    $flavour,
                    implode(', ', $known)
                ));
            }
        }
        return $this->addOperation('rawSql', array($byFlavour));
    }

    // ------------------------------------------------------------- rendering

    /**
     * Render every declared operation.
     *
     * @param AbstractGrammar|null $grammar Render for a different engine than the
     *   connected one - what --dry-run uses to show both.
     * @return array Statements, in declaration order.
     * @throws InvalidArgumentException If a rawSql() has no entry for this flavour.
     */
    public function toSql(AbstractGrammar $grammar = null)
    {
        $grammar = $grammar === null ? $this->grammar : $grammar;
        $statements = array();
        foreach ($this->operations as $index => $operation) {
            $statements = array_merge(
                $statements,
                $this->render($grammar, $operation, $index)
            );
        }
        return $statements;
    }

    /**
     * @return array The declared operations, unrendered.
     */
    public function operations()
    {
        return $this->operations;
    }

    /**
     * @return bool
     */
    public function isEmpty()
    {
        return empty($this->operations);
    }

    /**
     * Record an operation. Public because SchemaTableBuilder pushes through it;
     * migrations use the named methods.
     *
     * @param string $operation
     * @param array $arguments
     * @return $this
     */
    public function addOperation($operation, array $arguments)
    {
        if (!in_array($operation, self::$renderable, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown schema operation "%s". Known operations are: %s.',
                $operation,
                implode(', ', self::$renderable)
            ));
        }
        $this->operations[] = array('operation' => $operation, 'arguments' => $arguments);
        return $this;
    }

    /**
     * @param AbstractGrammar $grammar
     * @param array $operation
     * @param int $index Position in the declaration, for error messages.
     * @return array
     */
    private function render(AbstractGrammar $grammar, array $operation, $index)
    {
        if ($operation['operation'] === 'rawSql') {
            return $this->renderRawSql($grammar, $operation['arguments'][0], $index);
        }
        $rendered = call_user_func_array(
            array($grammar, $operation['operation']),
            $operation['arguments']
        );
        return (array)$rendered;
    }

    /**
     * @param AbstractGrammar $grammar
     * @param array $byFlavour
     * @param int $index
     * @return array
     * @throws InvalidArgumentException
     */
    private function renderRawSql(AbstractGrammar $grammar, array $byFlavour, $index)
    {
        $flavour = $grammar->flavour();
        if (!isset($byFlavour[$flavour])) {
            throw new InvalidArgumentException(sprintf(
                'rawSql() at position %d has no "%s" statement (it declares: %s). Every flavour must be spelled out - a migration that silently does nothing on one engine leaves that engine behind the code that expects it.',
                $index,
                $flavour,
                implode(', ', array_keys($byFlavour))
            ));
        }
        return (array)$byFlavour[$flavour];
    }
}
