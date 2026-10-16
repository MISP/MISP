<?php

App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('BaselineGenerator', 'Migration');
App::uses('Collation', 'Migration');
App::uses('MigrationDeferredException', 'Migration');
App::uses('SchemaBuilder', 'Migration');
App::uses('SchemaInspector', 'Migration');
App::uses('SchemaTargetGenerator', 'Migration');

/**
 * Brings one table to a target definition by declaring only what the live
 * table lacks, so that a table already at its target costs nothing and a run
 * that stopped halfway resumes with what is left.
 *
 * A target is what SchemaTargetGenerator produces and a TableMigration holds
 * as a frozen constant: 'options', 'columns' (DSL specs, the key flagged
 * `key => primary`), 'indexes' (the complete set by name, with 'pgsql' and
 * 'mysql' for an index the engines spell differently) and 'retired' (index
 * names to drop where a table has them).
 *
 * ## What counts as different
 *
 * - A column: its type as the reference's generator reads it (so mediumblob
 *   is binary, and an integer's display width is no difference), its length,
 *   sign, nullability, default and, on MySQL, its collation. An expression
 *   default the target does not have is a difference.
 * - An index: its columns, prefixes, uniqueness and kind, under the name the
 *   engine gives it. An index the target declares with its own PostgreSQL
 *   statement is compared there by name, uniqueness and method only.
 * - The table's engine, row format and default collation, on MySQL.
 *
 * ## What is done about it
 *
 * Missing columns are added; differing ones are redefined in full, the key
 * first; retired indexes are dropped, and so is a live index that duplicates
 * a target one (a non-unique one over a unique target's columns counts); an
 * index under a target name with another definition is rebuilt; missing ones
 * are added; the table options follow. Columns and indexes the target does
 * not know are the administrator's, and are kept and listed in the notes.
 * A primary key over other columns than the target's is not moved: the plan
 * names it as a blocker and converge() defers.
 */
class TableConverger
{
    /** What each DSL type is called by PostgreSQL's format_type(), without a length. */
    const PGSQL_TYPES = array(
        'integer' => 'integer',
        'biginteger' => 'bigint',
        'smallinteger' => 'smallint',
        'tinyinteger' => 'smallint',
        'boolean' => 'boolean',
        'string' => 'character varying',
        'text' => 'text',
        'mediumtext' => 'text',
        'longtext' => 'text',
        'binary' => 'bytea',
        'varbinary' => 'bytea',
        'datetime' => 'timestamp without time zone',
        'timestamp' => 'timestamp without time zone',
        'date' => 'date',
        'time' => 'time without time zone',
        'float' => 'double precision',
        'decimal' => 'numeric',
    );

    /** The DSL types whose length is part of the type, per engine. */
    const LENGTH_TYPES = array(
        AbstractGrammar::FLAVOUR_MYSQL => array('string', 'varbinary', 'decimal', 'datetime', 'timestamp'),
        AbstractGrammar::FLAVOUR_PGSQL => array('string', 'decimal'),
    );

    const STRING_TYPES = array('string', 'text', 'mediumtext', 'longtext');

    const INTEGER_TYPES = array('integer', 'biginteger', 'smallinteger', 'tinyinteger');

    /**
     * What the live table lacks, as data.
     *
     * @param SchemaInspector $inspector The live database.
     * @param string $table
     * @param array $target
     * @return array
     *   'table', 'exists' (false: the table is created),
     *   'create' => array('columns', 'options') when it does not exist,
     *   'add' => column => array('type', 'options'), missing columns in target order,
     *   'change' => column => array('type', 'options', 'differs' => list, 'from' => the live column), the key first,
     *   'dropIndexes' => name => why, the name as dropIndex() takes it,
     *   'addIndexes' => list of array('column', 'options') as addIndex() takes them,
     *   'options' => what changeOptions() sets,
     *   'notes' => lines for the administrator,
     *   'blockers' => why the table cannot be converged in place.
     * @throws LogicException On a malformed target.
     * @throws MigrationDeferredException When a collation cannot be resolved for this server.
     */
    public static function plan(SchemaInspector $inspector, $table, array $target)
    {
        self::assertTarget($table, $target);
        $live = $inspector->tableDefinition($table);
        if ($live === null) {
            return self::creation($table, $target);
        }
        $flavour = $inspector->flavour();
        $grammar = AbstractGrammar::offline($flavour);
        $plan = self::blank($table, true);
        $mysql = $flavour === AbstractGrammar::FLAVOUR_MYSQL;
        $version = $mysql ? $inspector->serverVersion() : null;

        self::planColumns($plan, $flavour, $version, $target, $live);
        self::planIndexes($plan, $grammar, $target, $live);
        if ($mysql) {
            self::planOptions($plan, $version, $target['options'], $live['options']);
        }
        return $plan;
    }

    /**
     * Declare what the live table lacks.
     *
     * @param SchemaInspector $inspector
     * @param SchemaBuilder $schema
     * @param string $table
     * @param array $target
     * @return array The plan.
     * @throws MigrationDeferredException When the plan has a blocker.
     */
    public static function converge(SchemaInspector $inspector, SchemaBuilder $schema, $table, array $target)
    {
        $plan = self::plan($inspector, $table, $target);
        if (!empty($plan['blockers'])) {
            throw new MigrationDeferredException(implode(' ', $plan['blockers']));
        }
        self::emit($schema, $plan);
        return $plan;
    }

    /**
     * Drop the table and create it empty at the target, unless it is there
     * already. For a table whose rows are rebuilt after the upgrade, where
     * converging would copy rows that are about to be thrown away.
     *
     * @param SchemaInspector $inspector
     * @param SchemaBuilder $schema
     * @param string $table
     * @param array $target
     * @return array The plan against the live table.
     */
    public static function recreate(SchemaInspector $inspector, SchemaBuilder $schema, $table, array $target)
    {
        $plan = self::plan($inspector, $table, $target);
        if (self::isEmpty($plan)) {
            return $plan;
        }
        if ($plan['exists']) {
            $schema->dropTable($table);
            $schema->note(sprintf('%s: recreated empty at the target', $table));
        }
        self::emit($schema, self::creation($table, $target));
        return $plan;
    }

    /**
     * Declare a plan's operations: column additions, which share a statement
     * only with each other, then the rebuild - index drops, column changes,
     * index additions, table options - as one statement on MySQL.
     *
     * @param SchemaBuilder $schema
     * @param array $plan
     * @return void
     */
    public static function emit(SchemaBuilder $schema, array $plan)
    {
        $table = $plan['table'];
        foreach ($plan['notes'] as $note) {
            $schema->note($note);
        }
        if (!$plan['exists']) {
            $schema->createTable($table, $plan['create']['columns'], $plan['create']['options']);
        }
        $builder = $schema->table($table);
        foreach ($plan['add'] as $column => $add) {
            $builder->addColumn($column, $add['type'], $add['options']);
        }
        foreach (array_keys($plan['dropIndexes']) as $name) {
            $builder->dropIndex($name);
        }
        foreach ($plan['change'] as $column => $change) {
            $builder->changeColumn($column, $change['type'], $change['options']);
        }
        foreach ($plan['addIndexes'] as $index) {
            $builder->addIndex($index['column'], $index['options']);
        }
        if (!empty($plan['options'])) {
            $builder->changeOptions($plan['options']);
        }
    }

    /**
     * @param array $plan
     * @return bool Whether the table is at its target.
     */
    public static function isEmpty(array $plan)
    {
        foreach (array('blockers', 'add', 'change', 'dropIndexes', 'addIndexes', 'options') as $part) {
            if (!empty($plan[$part])) {
                return false;
            }
        }
        return $plan['exists'];
    }

    // ---------------------------------------------------------------- tables

    /**
     * @param string $table
     * @param bool $exists
     * @return array
     */
    private static function blank($table, $exists)
    {
        return array(
            'table' => $table,
            'exists' => $exists,
            'add' => array(),
            'change' => array(),
            'dropIndexes' => array(),
            'addIndexes' => array(),
            'options' => array(),
            'notes' => array(),
            'blockers' => array(),
        );
    }

    /**
     * The plan for a table that is not there: create it, then add its
     * indexes, every engine's, since there is nothing to compare.
     *
     * @param string $table
     * @param array $target
     * @return array
     */
    private static function creation($table, array $target)
    {
        $plan = self::blank($table, false);
        $plan['create'] = array('columns' => $target['columns'], 'options' => $target['options']);
        foreach ($target['indexes'] as $key => $index) {
            $plan['addIndexes'][] = self::declaration($key, $index, $target['columns']);
        }
        return $plan;
    }

    /**
     * @param string $table
     * @param array $target
     * @return void
     * @throws LogicException
     */
    private static function assertTarget($table, array $target)
    {
        if (!is_string($table) || $table === '') {
            throw new LogicException('A table to converge needs a name.');
        }
        foreach (array('options', 'columns', 'indexes') as $part) {
            if (!isset($target[$part]) || !is_array($target[$part])) {
                throw new LogicException(sprintf('The target of %s has no %s.', $table, $part));
            }
        }
        $keys = array();
        foreach ($target['columns'] as $column => $spec) {
            if (!isset($spec['type'])) {
                throw new LogicException(sprintf('%s.%s has no type in its target.', $table, $column));
            }
            if (self::isKey($spec)) {
                $keys[] = $column;
                if (in_array($spec['type'], self::INTEGER_TYPES, true) && $spec['type'] !== 'biginteger') {
                    throw new LogicException(sprintf('%s.%s: an integer key is a biginteger in a target.', $table, $column));
                }
            }
        }
        if (count($keys) > 1) {
            throw new LogicException(sprintf('The target of %s keys on %s; a key is one column.', $table, implode(', ', $keys)));
        }
    }

    /**
     * @param array $spec
     * @return bool
     */
    private static function isKey(array $spec)
    {
        return isset($spec['key']) && $spec['key'] === 'primary';
    }

    // --------------------------------------------------------------- columns

    /**
     * @param array $plan
     * @param string $flavour
     * @param string|null $version
     * @param array $target
     * @param array $live tableDefinition()
     * @return void
     */
    private static function planColumns(array &$plan, $flavour, $version, array $target, array $live)
    {
        $table = $plan['table'];
        $mysql = $flavour === AbstractGrammar::FLAVOUR_MYSQL;
        $liveColumns = self::byFoldedName($live['columns'], $mysql);
        $tableCollation = isset($target['options']['collate']) ? $target['options']['collate'] : null;

        $key = null;
        $previous = null;
        $changes = array();
        foreach ($target['columns'] as $column => $spec) {
            if (self::isKey($spec)) {
                $key = $column;
            }
            $folded = self::fold($column, $mysql);
            if (!isset($liveColumns[$folded])) {
                $options = self::columnOptions($spec);
                if ($mysql) {
                    $options += $previous === null ? array('first' => true) : array('after' => $previous);
                }
                $plan['add'][$column] = array('type' => $spec['type'], 'options' => $options);
                $previous = $column;
                continue;
            }
            $previous = $column;
            $from = $liveColumns[$folded];
            $differs = self::columnDiffers($spec, $from, $flavour, $version, $tableCollation);
            if (empty($differs)) {
                continue;
            }
            $change = self::isKey($spec) && $spec['type'] === 'biginteger'
                ? array('type' => 'primary_key', 'options' => array())
                : array(
                    'type' => $spec['type'],
                    'options' => self::columnOptions($spec) + array('null' => true, 'default' => null),
                );
            $changes[$column] = $change + array('differs' => $differs, 'from' => $from);
        }
        if ($key !== null && isset($changes[$key])) {
            $changes = array($key => $changes[$key]) + $changes;
        }
        $plan['change'] = $changes;

        $livePrimary = isset($live['indexes']['PRIMARY']['column']) ? $live['indexes']['PRIMARY']['column'] : array();
        $wanted = $key === null ? array() : array($key);
        if (self::foldAll($livePrimary, $mysql) !== self::foldAll($wanted, $mysql)) {
            $plan['blockers'][] = sprintf(
                '%s: the primary key is %s and the target keys on %s; a migration does not move a primary key, so that is done by hand first.',
                $table,
                empty($livePrimary) ? 'missing' : '(' . implode(', ', $livePrimary) . ')',
                empty($wanted) ? 'nothing' : '(' . $key . ')'
            );
        }

        $targetColumns = self::byFoldedName($target['columns'], $mysql);
        foreach (array_keys($live['columns']) as $column) {
            if (!isset($targetColumns[self::fold($column, $mysql)])) {
                $plan['notes'][] = sprintf('%s: column %s is not in the target; kept', $table, $column);
            }
        }
    }

    /**
     * A target column spec as addColumn() and changeColumn() take it.
     *
     * @param array $spec
     * @return array
     */
    private static function columnOptions(array $spec)
    {
        unset($spec['type'], $spec['key']);
        return $spec;
    }

    /**
     * @param array $spec The target's.
     * @param array $live tableDefinition()'s.
     * @param string $flavour
     * @param string|null $version
     * @param string|null $tableCollation
     * @return array What differs: type, length, unsigned, null, increment, default, collation.
     */
    private static function columnDiffers(array $spec, array $live, $flavour, $version, $tableCollation)
    {
        $mysql = $flavour === AbstractGrammar::FLAVOUR_MYSQL;
        $type = $spec['type'];
        $differs = array();
        if (!self::sameType($type, $live, $mysql)) {
            $differs[] = 'type';
        } elseif (self::lengthDiffers($spec, $live, $flavour)) {
            $differs[] = 'length';
        }
        if ($mysql && !empty($spec['unsigned']) !== !empty($live['unsigned'])) {
            $differs[] = 'unsigned';
        }
        $nullable = !array_key_exists('null', $spec) || !empty($spec['null']);
        if ($nullable !== !empty($live['null'])) {
            $differs[] = 'null';
        }
        if (self::isKey($spec) && in_array($type, self::INTEGER_TYPES, true)) {
            if ($live['increment'] !== ($mysql ? 'auto_increment' : 'identity')) {
                $differs[] = 'increment';
            }
        } elseif (self::targetDefault($spec) !== self::liveDefault($live, $type)) {
            $differs[] = 'default';
        }
        if ($mysql && in_array($type, self::STRING_TYPES, true)) {
            $collate = isset($spec['collate']) ? $spec['collate'] : $tableCollation;
            if ($collate !== null && strcasecmp(self::collation($collate, $version), (string)$live['collation']) !== 0) {
                $differs[] = 'collation';
            }
        }
        return $differs;
    }

    /**
     * @param string $type
     * @param array $live
     * @param bool $mysql
     * @return bool
     */
    private static function sameType($type, array $live, $mysql)
    {
        if ($mysql) {
            return BaselineGenerator::dslType($live['type']) === $type;
        }
        return isset(self::PGSQL_TYPES[$type]) && self::PGSQL_TYPES[$type] === $live['base'];
    }

    /**
     * @param array $spec
     * @param array $live
     * @param string $flavour
     * @return bool
     */
    private static function lengthDiffers(array $spec, array $live, $flavour)
    {
        $type = $spec['type'];
        if (!in_array($type, self::LENGTH_TYPES[$flavour], true)) {
            return false;
        }
        $wanted = isset($spec['length']) ? str_replace(' ', '', (string)$spec['length']) : ($type === 'string' ? '255' : '');
        $actual = $live['length'] === null ? '' : $live['length'] . ($live['scale'] === null ? '' : ',' . $live['scale']);
        return $wanted !== (string)$actual;
    }

    /**
     * @param array $spec
     * @return string|null
     */
    private static function targetDefault(array $spec)
    {
        if (!array_key_exists('default', $spec) || $spec['default'] === null) {
            return null;
        }
        return self::normaliseDefault($spec['default'], false, $spec['type']);
    }

    /**
     * @param array $live
     * @param string $type The target's.
     * @return string|null
     */
    private static function liveDefault(array $live, $type)
    {
        if ($live['default'] === null) {
            return null;
        }
        return self::normaliseDefault($live['default'], !empty($live['default_expression']), $type);
    }

    /**
     * One spelling per default across the servers: MariaDB's current_timestamp()
     * and PostgreSQL's false read as what a target says, CURRENT_TIMESTAMP and 0.
     *
     * @param mixed $value
     * @param bool $isExpression
     * @param string $type
     * @return string
     */
    private static function normaliseDefault($value, $isExpression, $type)
    {
        $value = is_bool($value) ? ($value ? '1' : '0') : (string)$value;
        $temporal = in_array($type, array('datetime', 'timestamp'), true);
        if ($isExpression || ($temporal && strcasecmp($value, 'CURRENT_TIMESTAMP') === 0)) {
            $expression = strtolower(str_replace(' ', '', $value));
            if (in_array($expression, array('current_timestamp', 'current_timestamp()', 'now()'), true)) {
                $expression = 'current_timestamp';
            }
            return 'expression:' . $expression;
        }
        if ($type === 'boolean') {
            $lower = strtolower($value);
            if (in_array($lower, array('1', 't', 'true'), true)) {
                return '1';
            }
            if (in_array($lower, array('0', 'f', 'false'), true)) {
                return '0';
            }
        }
        return $value;
    }

    /**
     * @param string $collate A token or a collation name.
     * @param string $version
     * @return string The collation as this server names it.
     * @throws MigrationDeferredException
     */
    private static function collation($collate, $version)
    {
        if (!Collation::isToken($collate)) {
            return $collate;
        }
        $resolved = Collation::forServer($collate, $version);
        return $resolved['collate'];
    }

    // --------------------------------------------------------------- indexes

    /**
     * @param array $plan
     * @param AbstractGrammar $grammar Names the indexes as the live engine does.
     * @param array $target
     * @param array $live
     * @return void
     */
    private static function planIndexes(array &$plan, AbstractGrammar $grammar, array $target, array $live)
    {
        $table = $plan['table'];
        $mysql = $grammar->flavour() === AbstractGrammar::FLAVOUR_MYSQL;
        $wanted = self::targetIndexes($grammar, $table, $target);

        $retired = array();
        foreach (isset($target['retired']) ? $target['retired'] : array() as $name) {
            $retired[self::fold($grammar->indexName($table, $name), $mysql)] = $name;
        }

        $present = array();
        foreach ($live['indexes'] as $key => $index) {
            if ($key === 'PRIMARY') {
                continue;
            }
            $physical = $index['name'];
            $folded = self::fold($physical, $mysql);
            $shape = self::liveShape($index, $mysql);
            if (isset($wanted[$folded])) {
                if (self::matches($wanted[$folded]['shape'], $shape)) {
                    $present[$folded] = true;
                    continue;
                }
                $plan['dropIndexes'][self::dropName($grammar, $table, $wanted[$folded]['key'], $physical)] = 'redefined';
                $plan['notes'][] = sprintf(
                    '%s: index %s is %s; the target has it as %s, so it is rebuilt',
                    $table,
                    $physical,
                    self::describe($shape),
                    self::describe($wanted[$folded]['shape'])
                );
                continue;
            }
            if (isset($retired[$folded])) {
                $plan['dropIndexes'][$retired[$folded]] = 'retired';
                continue;
            }
            $twin = self::twinOf($shape, $wanted, $mysql);
            $name = $twin === null ? null : self::dropName($grammar, $table, null, $physical);
            if ($name !== null) {
                $plan['dropIndexes'][$name] = 'duplicate';
                $plan['notes'][] = sprintf('%s: index %s duplicates the target index %s; dropped', $table, $physical, $twin);
                continue;
            }
            $cover = $index['expression'] ? null : SchemaTargetGenerator::coveringIndex(array(
                'column' => $index['column'],
                'unique' => $index['unique'],
                'fulltext' => $index['type'] === 'fulltext',
                'length' => $index['length'],
            ), $target['indexes']);
            $plan['notes'][] = sprintf(
                '%s: index %s %s is not in the target; kept%s',
                $table,
                $physical,
                self::describe($shape),
                $cover === null ? '' : sprintf(' (the target index %s starts with the same columns)', $cover)
            );
        }

        foreach ($wanted as $folded => $index) {
            if (empty($present[$folded])) {
                $plan['addIndexes'][] = $index['declaration'];
            }
        }
    }

    /**
     * The target's indexes on this engine, by folded physical name.
     *
     * @param AbstractGrammar $grammar
     * @param string $table
     * @param array $target
     * @return array name => array('key', 'name', 'declaration', 'shape')
     */
    private static function targetIndexes(AbstractGrammar $grammar, $table, array $target)
    {
        $mysql = $grammar->flavour() === AbstractGrammar::FLAVOUR_MYSQL;
        $indexes = array();
        foreach ($target['indexes'] as $key => $index) {
            if ($mysql && isset($index['mysql']) && $index['mysql'] === false) {
                continue;
            }
            $declaration = self::declaration($key, $index, $target['columns']);
            $name = $grammar->indexName($table, $declaration['column'], $declaration['options']);
            $indexes[self::fold($name, $mysql)] = array(
                'key' => $key,
                'name' => $name,
                'declaration' => $declaration,
                'shape' => self::targetShape($declaration, $mysql),
            );
        }
        return $indexes;
    }

    /**
     * A target index as addIndex() takes it. A non-unique prefix index on one
     * text column becomes a hash index on PostgreSQL, which has no prefixes
     * and would otherwise index whole values past its btree entry limit.
     *
     * @param string $key
     * @param array $index
     * @param array $columns The target's.
     * @return array array('column' => list, 'options' => array)
     */
    private static function declaration($key, array $index, array $columns)
    {
        $columnList = isset($index['column']) ? array_values($index['column']) : array($key);
        $options = array('name' => $key);
        foreach (array('unique', 'fulltext', 'length', 'mysql', 'pgsql') as $option) {
            if (isset($index[$option])) {
                $options[$option] = $index[$option];
            }
        }
        if (!isset($options['pgsql']['sql'])
            && BaselineGenerator::needsHashRewrite(array('column' => $columnList) + $index, $columns)
        ) {
            $options['pgsql']['sql'] = sprintf(
                'CREATE INDEX %%1$s ON %%2$s USING hash ("%s");',
                str_replace('"', '""', $columnList[0])
            );
        }
        return array('column' => $columnList, 'options' => $options);
    }

    /**
     * What is compared of a target index. One with its own PostgreSQL
     * statement is compared by uniqueness and method alone, as read off that
     * statement.
     *
     * @param array $declaration
     * @param bool $mysql
     * @return array
     */
    private static function targetShape(array $declaration, $mysql)
    {
        $options = $declaration['options'];
        if ($mysql) {
            return self::mysqlShape(
                $declaration['column'],
                !empty($options['unique']),
                !empty($options['fulltext']),
                isset($options['length']) ? $options['length'] : array()
            );
        }
        if (isset($options['pgsql']['sql'])) {
            $sql = $options['pgsql']['sql'];
            return array(
                'column' => null,
                'unique' => (bool)preg_match('/^\s*CREATE\s+UNIQUE\s/i', $sql),
                'method' => preg_match('/\bUSING\s+(\w+)/i', $sql, $m) ? strtolower($m[1]) : 'btree',
            );
        }
        return array('column' => $declaration['column'], 'unique' => !empty($options['unique']), 'method' => 'btree');
    }

    /**
     * @param array $index tableDefinition()'s.
     * @param bool $mysql
     * @return array
     */
    private static function liveShape(array $index, $mysql)
    {
        if ($mysql) {
            return self::mysqlShape($index['column'], $index['unique'], $index['type'] === 'fulltext', $index['length']);
        }
        return array('column' => $index['column'], 'unique' => (bool)$index['unique'], 'method' => $index['type']);
    }

    /**
     * @param array $columns
     * @param bool $unique
     * @param bool $fulltext
     * @param array|int $length column => prefix, or one prefix for a single column.
     * @return array
     */
    private static function mysqlShape(array $columns, $unique, $fulltext, $length)
    {
        $columns = array_values($columns);
        if (!is_array($length)) {
            $length = array($columns[0] => $length);
        }
        $prefixes = array();
        foreach ($length as $column => $prefix) {
            $prefixes[strtolower($column)] = (int)$prefix;
        }
        ksort($prefixes);
        return array(
            'column' => self::foldAll($columns, true),
            'unique' => (bool)$unique,
            'fulltext' => (bool)$fulltext,
            'length' => $prefixes,
        );
    }

    /**
     * @param array $wanted A target index's shape.
     * @param array $live A live index's.
     * @return bool
     */
    private static function matches(array $wanted, array $live)
    {
        if ($wanted['column'] === null) {
            return $wanted['unique'] === $live['unique'] && $wanted['method'] === $live['method'];
        }
        return $wanted === $live;
    }

    /**
     * The target index a live one duplicates: the same definition, or a
     * non-unique one over what a unique target index covers.
     *
     * @param array $shape The live index's.
     * @param array $wanted targetIndexes()
     * @param bool $mysql
     * @return string|null The target index's name.
     */
    private static function twinOf(array $shape, array $wanted, $mysql)
    {
        foreach ($wanted as $index) {
            $theirs = $index['shape'];
            if ((!$mysql && $theirs['column'] === null) || ($shape['unique'] && !$theirs['unique'])) {
                continue;
            }
            $candidate = $shape;
            $candidate['unique'] = $theirs['unique'];
            if ($candidate === $theirs) {
                return $index['name'];
            }
        }
        return null;
    }

    /**
     * The name dropIndex() needs for a live index: the target's own name
     * where the engine derives the physical one from it, else the physical
     * name where the engine takes it as it is.
     *
     * @param AbstractGrammar $grammar
     * @param string $table
     * @param string|null $key
     * @param string $physical
     * @return string|null Null when dropIndex() cannot address it.
     */
    private static function dropName(AbstractGrammar $grammar, $table, $key, $physical)
    {
        $mysql = $grammar->flavour() === AbstractGrammar::FLAVOUR_MYSQL;
        foreach (array($key, $physical) as $candidate) {
            if ($candidate !== null
                && self::fold($grammar->indexName($table, $candidate), $mysql) === self::fold($physical, $mysql)
            ) {
                return $candidate;
            }
        }
        return null;
    }

    /**
     * @param array $shape
     * @return string
     */
    private static function describe(array $shape)
    {
        if ($shape['column'] === null) {
            $out = '(its own statement)';
        } else {
            $parts = array();
            foreach ($shape['column'] as $column) {
                $prefix = isset($shape['length'][$column]) ? '(' . $shape['length'][$column] . ')' : '';
                $parts[] = $column . $prefix;
            }
            $out = '(' . implode(', ', $parts) . ')';
        }
        if ($shape['unique']) {
            $out = 'unique ' . $out;
        }
        if (!empty($shape['fulltext'])) {
            $out = 'fulltext ' . $out;
        }
        if (isset($shape['method']) && $shape['method'] !== 'btree') {
            $out .= ' using ' . $shape['method'];
        }
        return $out;
    }

    // --------------------------------------------------------------- options

    /**
     * @param array $plan
     * @param string $version
     * @param array $wanted The target's options.
     * @param array $live tableDefinition()'s options.
     * @return void
     */
    private static function planOptions(array &$plan, $version, array $wanted, array $live)
    {
        if (isset($wanted['engine']) && strcasecmp($wanted['engine'], (string)$live['engine']) !== 0) {
            $plan['options']['engine'] = $wanted['engine'];
        }
        if (isset($wanted['row_format']) && strtoupper($wanted['row_format']) !== $live['row_format']) {
            $plan['options']['row_format'] = $wanted['row_format'];
        }
        if (isset($wanted['collate'])
            && strcasecmp(self::collation($wanted['collate'], $version), (string)$live['collation']) !== 0
        ) {
            $plan['options']['collate'] = $wanted['collate'];
            if (isset($wanted['charset'])) {
                $plan['options']['charset'] = $wanted['charset'];
            }
        }
    }

    // --------------------------------------------------------------- helpers

    /**
     * MySQL compares column and index names without regard to case.
     *
     * @param string|null $name
     * @param bool $mysql
     * @return string|null
     */
    private static function fold($name, $mysql)
    {
        return $mysql && $name !== null ? strtolower($name) : $name;
    }

    /**
     * @param array $names
     * @param bool $mysql
     * @return array
     */
    private static function foldAll(array $names, $mysql)
    {
        $folded = array();
        foreach ($names as $name) {
            $folded[] = self::fold($name, $mysql);
        }
        return $folded;
    }

    /**
     * @param array $columns name => anything
     * @param bool $mysql
     * @return array folded name => the same
     */
    private static function byFoldedName(array $columns, $mysql)
    {
        $folded = array();
        foreach ($columns as $name => $value) {
            $folded[self::fold($name, $mysql)] = $value;
        }
        return $folded;
    }
}
