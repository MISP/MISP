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
 * ## One statement per table
 *
 * Consecutive operations on the same table are rendered together, as one
 * ALTER TABLE, because on MySQL every ALTER TABLE may rebuild the table: ten
 * separate changes to `attributes` would copy it ten times. PostgreSQL gets
 * one ALTER TABLE for the column changes, with its index statements in their
 * place around it.
 *
 * Two things start a new statement instead:
 *
 * - **A column addition or drop next to anything else.** On its own it is
 *   instant on both MySQL and MariaDB. Beside an operation that cannot be
 *   instant, such as an index change, the server falls back to rebuilding the
 *   whole table for it. So additions and drops share a statement only with
 *   each other.
 * - **An operation that depends on an earlier one in the statement.** Inside
 *   one statement MySQL resolves column clauses against the table as it was,
 *   so a few sequences that work as separate statements fail as one: naming a
 *   column an earlier operation already named, dropping or renaming a column
 *   an index added in the statement covers, dropping an index added in the
 *   statement. Splitting costs at most a second rebuild, so the rule splits
 *   whenever it is in doubt.
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
        foreach ($this->batches($grammar) as $index => $batch) {
            $rendered = $this->isAlter($batch[0])
                ? $grammar->alterTable($batch[0]['arguments'][0], $batch)
                : $this->render($grammar, $batch[0], $index);
            $statements = array_merge($statements, $rendered);
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
     * The declared operations, grouped into what renders as one statement.
     *
     * @param AbstractGrammar $grammar For the index names, which differ by engine.
     * @return array Lists of operations, keyed by the position of the first.
     */
    private function batches(AbstractGrammar $grammar)
    {
        $batches = array();
        $start = null;
        $table = null;
        // Of the open ALTER TABLE; null while none is open.
        $footprint = null;
        foreach ($this->operations as $index => $operation) {
            if (!$this->isAlter($operation)) {
                $batches[$index] = array($operation);
                $footprint = null;
                continue;
            }
            $next = $this->footprint($grammar, $operation);
            if (
                $footprint !== null &&
                $operation['arguments'][0] === $table &&
                $this->canJoin($footprint, $next)
            ) {
                $batches[$start][] = $operation;
                foreach ($next['names'] as $key => $names) {
                    $footprint['names'][$key] = array_merge($footprint['names'][$key], $names);
                }
                continue;
            }
            $batches[$index] = array($operation);
            $start = $index;
            $table = $operation['arguments'][0];
            $footprint = $next;
        }
        return $batches;
    }

    /**
     * @param array $operation
     * @return bool
     */
    private function isAlter(array $operation)
    {
        return in_array($operation['operation'], AbstractGrammar::ALTER_OPERATIONS, true);
    }

    /**
     * What an operation on an existing table touches: whether it adds or drops
     * a column, and the names it involves - the columns it names, the columns
     * it removes, the indexes it adds or drops, and the columns the added ones
     * cover.
     *
     * @param AbstractGrammar $grammar
     * @param array $operation
     * @return array
     */
    private function footprint(AbstractGrammar $grammar, array $operation)
    {
        $arguments = $operation['arguments'];
        $table = $arguments[0];
        $names = array(
            'columns' => array(),
            'removes' => array(),
            'indexedColumns' => array(),
            'addsIndexes' => array(),
            'dropsIndexes' => array(),
        );
        $options = array();
        switch ($operation['operation']) {
            case 'addColumn':
            case 'changeColumn':
                $names['columns'][] = $arguments[1];
                $options = $arguments[3];
                break;
            case 'renameColumn':
                $names['columns'] = array($arguments[1], $arguments[2]);
                $names['removes'][] = $arguments[1];
                $options = $arguments[4];
                break;
            case 'dropColumn':
                $names['columns'][] = $arguments[1];
                $names['removes'][] = $arguments[1];
                break;
            case 'addIndex':
                $names['indexedColumns'] = array_values((array)$arguments[1]);
                $names['addsIndexes'][] = $grammar->indexName($table, $arguments[1], $arguments[2]);
                break;
            case 'dropIndex':
                $names['dropsIndexes'][] = $grammar->indexName($table, $arguments[1]);
                break;
        }
        if (!empty($options['after'])) {
            $names['columns'][] = $options['after'];
        }
        $addsOrDrops = in_array($operation['operation'], array('addColumn', 'dropColumn'), true);
        return array('addsOrDropsColumn' => $addsOrDrops, 'names' => $names);
    }

    /**
     * Whether an operation can join the statement the earlier ones form
     * without costing a rebuild the separate statements would not, or giving
     * a result they would not.
     *
     * @param array $batch The footprint of the statement so far.
     * @param array $next The operation's own footprint.
     * @return bool
     */
    private function canJoin(array $batch, array $next)
    {
        $joined = $batch['names'];
        $names = $next['names'];
        return $batch['addsOrDropsColumn'] === $next['addsOrDropsColumn']
            && !array_intersect($names['columns'], $joined['columns'])
            && !array_intersect($names['removes'], $joined['indexedColumns'])
            && !array_intersect($names['dropsIndexes'], $joined['addsIndexes']);
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
