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
 * ## What is already there is left out
 *
 * skipSatisfied() checks the declaration against the live schema before it is
 * rendered: a column or index that is already there is not added again, one
 * that is already gone is not dropped again. A migration that stopped halfway
 * then re-runs as just the part that did not land, and no statement carries a
 * clause the server would refuse - which matters, because when one clause of
 * an ALTER TABLE fails, none of them is made.
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
     * Drop the operations whose result the database already has.
     *
     * Each operation is checked against the schema as the ones kept before it
     * would leave it, so dropping an index and adding it back under the same
     * name keeps both. Tables and indexes are matched by name, the way the
     * server refuses a duplicate. A column change is never left out, and
     * nothing after a rawSql() is, since what hand-written SQL changes cannot
     * be known.
     *
     * A table that is already there still gets whichever of its declared
     * indexes it lacks: on PostgreSQL those are statements of their own, so a
     * run that stopped after the CREATE TABLE leaves the table without them.
     *
     * @param SchemaInspector $inspector The live schema. It must read the engine
     *   this builder's grammar names indexes for.
     * @return array One line per operation left out.
     * @throws LogicException When the inspector reads another engine.
     */
    public function skipSatisfied(SchemaInspector $inspector)
    {
        if ($inspector->flavour() !== $this->grammar->flavour()) {
            throw new LogicException(sprintf(
                'A %s schema cannot tell what a %s declaration still needs.',
                $inspector->flavour(),
                $this->grammar->flavour()
            ));
        }
        $tables = array();
        $kept = array();
        $skipped = array();
        $opaque = false;
        foreach ($this->operations as $index => $operation) {
            $opaque = $opaque || $operation['operation'] === 'rawSql';
            $note = $opaque ? null : $this->satisfied($inspector, $tables, $operation);
            if ($note === null) {
                $kept[$index] = $operation;
                continue;
            }
            $skipped[] = $note;
            if ($operation['operation'] === 'createTable') {
                foreach ($this->declaredIndexes($operation) as $n => $addIndex) {
                    if ($this->satisfied($inspector, $tables, $addIndex) === null) {
                        $kept[$index . '.' . $n] = $addIndex;
                    }
                }
            }
        }
        $this->operations = $kept;
        return $skipped;
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
     * Whether the database already has what an operation would do, and if not,
     * the table as it will be once the operation has run.
     *
     * @param SchemaInspector $inspector
     * @param array $tables Table => tableState().
     * @param array $operation
     * @return string|null Why the operation can be left out; null to keep it.
     */
    private function satisfied(SchemaInspector $inspector, array &$tables, array $operation)
    {
        $arguments = $operation['arguments'];
        $table = $arguments[0];
        $state = $this->tableState($inspector, $tables, $table);
        switch ($operation['operation']) {
            case 'createTable':
                if (is_array($state)) {
                    return sprintf('%s: the table is already there', $table);
                }
                // Its shape is the declaration's, which later operations on it
                // were written against.
                $tables[$table] = null;
                return null;
            case 'dropTable':
                if ($state === false) {
                    return sprintf('%s: the table is already gone', $table);
                }
                $tables[$table] = false;
                return null;
            case 'renameTable':
                $to = $arguments[1];
                if ($state === false && is_array($this->tableState($inspector, $tables, $to))) {
                    return sprintf('%s: the table is already renamed to %s', $table, $to);
                }
                $tables[$to] = $state;
                $tables[$table] = false;
                return null;
        }
        if (!is_array($state)) {
            return null;
        }
        switch ($operation['operation']) {
            case 'addColumn':
                $column = $this->fold($arguments[1]);
                if (isset($state['columns'][$column])) {
                    return sprintf('%s: column %s is already there', $table, $arguments[1]);
                }
                $state['columns'][$column] = true;
                $options = $arguments[3];
                if (
                    $arguments[2] === 'primary_key' ||
                    (isset($options['key']) && $options['key'] === 'primary')
                ) {
                    $state['primary'] = array($column);
                }
                break;
            case 'dropColumn':
                $column = $this->fold($arguments[1]);
                if (!isset($state['columns'][$column])) {
                    return sprintf('%s: column %s is already gone', $table, $arguments[1]);
                }
                unset($state['columns'][$column]);
                $state = $this->forgetIndexesOver($state, $column);
                break;
            case 'renameColumn':
                $from = $this->fold($arguments[1]);
                $to = $this->fold($arguments[2]);
                if (!isset($state['columns'][$from]) && isset($state['columns'][$to])) {
                    return sprintf(
                        '%s: column %s is already renamed to %s',
                        $table,
                        $arguments[1],
                        $arguments[2]
                    );
                }
                unset($state['columns'][$from]);
                $state['columns'][$to] = true;
                $state = $this->forgetIndexesOver($state, $from);
                break;
            case 'addIndex':
                $name = $this->grammar->indexName($table, $arguments[1], $arguments[2]);
                if (isset($state['indexes'][$this->fold($name)])) {
                    return sprintf('%s: index %s is already there', $table, $name);
                }
                $columns = array_map(array($this, 'fold'), (array)$arguments[1]);
                $state['indexes'][$this->fold($name)] = $columns;
                break;
            case 'dropIndex':
                $name = $this->grammar->indexName($table, $arguments[1]);
                if (!array_key_exists($this->fold($name), $state['indexes'])) {
                    return sprintf('%s: index %s is already gone', $table, $name);
                }
                unset($state['indexes'][$this->fold($name)]);
                break;
            case 'dropPrimaryKey':
                if ($state['primary'] === array()) {
                    return sprintf('%s: the primary key is already gone', $table);
                }
                $state['primary'] = array();
                break;
        }
        $tables[$table] = $state;
        return null;
    }

    /**
     * A table as the live schema has it: its columns, its indexes by name with
     * the columns they cover, and its primary key's columns. Names are folded
     * the way the engine compares them.
     *
     * @param SchemaInspector $inspector
     * @param array $tables
     * @param string $table
     * @return array|false|null False when the table is not there; null when an
     *   earlier operation created it or moved it in, so its shape is not known.
     */
    private function tableState(SchemaInspector $inspector, array &$tables, $table)
    {
        if (array_key_exists($table, $tables)) {
            return $tables[$table];
        }
        $tables[$table] = false;
        if (!$inspector->hasTable($table)) {
            return false;
        }
        $state = array('columns' => array(), 'indexes' => array(), 'primary' => array());
        foreach (array_keys($inspector->columns($table)) as $column) {
            $state['columns'][$this->fold($column)] = true;
        }
        foreach ($inspector->indexes($table) as $name => $index) {
            $columns = isset($index['column']) ? (array)$index['column'] : array();
            $columns = array_map(array($this, 'fold'), $columns);
            if ($name === 'PRIMARY') {
                $state['primary'] = $columns;
            } else {
                $state['indexes'][$this->fold($name)] = $columns;
            }
        }
        return $tables[$table] = $state;
    }

    /**
     * A createTable()'s indexes, each as the addIndex() that adds it alone.
     *
     * @param array $operation
     * @return array
     */
    private function declaredIndexes(array $operation)
    {
        list($table, , $options) = $operation['arguments'];
        $indexes = isset($options['indexes']) ? $options['indexes'] : array();
        $operations = array();
        foreach ($indexes as $key => $indexOptions) {
            list($columns, $indexOptions) = $this->grammar->normaliseIndexDeclaration($key, $indexOptions);
            $operations[] = array(
                'operation' => 'addIndex',
                'arguments' => array($table, $columns, $indexOptions),
            );
        }
        return $operations;
    }

    /**
     * Dropping or renaming a column changes the indexes over it differently on
     * each engine, so from then on they count as unknown: an operation on one
     * is kept rather than guessed about.
     *
     * @param array $state
     * @param string $column Folded.
     * @return array
     */
    private function forgetIndexesOver(array $state, $column)
    {
        foreach ($state['indexes'] as $name => $columns) {
            if ($columns === null || in_array($column, $columns, true)) {
                $state['indexes'][$name] = null;
            }
        }
        if ($state['primary'] === null || in_array($column, $state['primary'], true)) {
            $state['primary'] = null;
        }
        return $state;
    }

    /**
     * MySQL compares column and index names without regard to case.
     *
     * @param string $name
     * @return string
     */
    private function fold($name)
    {
        return $this->grammar->flavour() === AbstractGrammar::FLAVOUR_MYSQL ? strtolower($name) : $name;
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
