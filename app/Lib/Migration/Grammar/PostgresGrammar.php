<?php

App::uses('AbstractGrammar', 'Migration/Grammar');

/**
 * PostgreSQL rendering.
 *
 * The interesting engine, because this is where the flavour-agnostic promise
 * has to be paid for. Three kinds of divergence live here.
 *
 * **Hints that are dropped.** `after` is cosmetic column ordering and PostgreSQL
 * has no equivalent, so it goes. charset, collate, comment, unsigned and the
 * table's ENGINE go too, but not by anything written here - Cake's Postgres
 * driver declares neither $fieldParameters nor $tableParameters, so those
 * simply never render. A prefix length is different in kind: dropping it
 * changes what the index indexes, so it is recorded in $droppedHints for the
 * caller to log rather than disappearing quietly.
 *
 * **Statements that have a different shape.** MySQL's MODIFY carries type,
 * nullability and default in one clause; PostgreSQL splits them into ALTER
 * COLUMN ... TYPE ... USING, SET/DROP NOT NULL and SET/DROP DEFAULT. Indexes are
 * not create-table clauses but statements of their own. Which is why every
 * grammar method returns an array of statements.
 *
 * **Things with no rendering at all.** FULLTEXT is rejected outright, with a
 * message pointing at rawSql() - a migration that quietly does nothing on one
 * engine is precisely the silently-skipped-migration failure this whole
 * subsystem exists to end.
 *
 * ## Index names are schema-global
 *
 * On MySQL an index name only has to be unique within its table, and the corpus
 * leans on that - dozens of tables have an index plainly called `uuid`. On
 * PostgreSQL index names share one namespace per schema, so every name is
 * prefixed with idx_<table>_. That is the convention AppModel::__addIndex()
 * already used on its PostgreSQL branch, so existing instances match.
 */
class PostgresGrammar extends AbstractGrammar
{
    /**
     * MISP types Cake's Postgres map does not define. mediumtext and longtext
     * are MySQL storage tiers of one logical type, so both collapse to text.
     *
     * @var array
     */
    protected $extraColumns = array(
        'mediumtext' => array('name' => 'text'),
        'longtext' => array('name' => 'text'),
        'varbinary' => array('name' => 'bytea'),
    );

    /**
     * Rendered type names that accept a length modifier. Everything else has any
     * length stripped - see mergedColumns().
     *
     * @var array
     */
    private static $lengthBearingTypes = array(
        'varchar',
        'char',
        'character varying',
        'decimal',
        'numeric',
        'float',
    );

    public function flavour()
    {
        return self::FLAVOUR_PGSQL;
    }

    // ---------------------------------------------------------------- schema

    public function createTable($table, array $columns, array $options = array())
    {
        list($specs, $primaryKey) = $this->partitionColumns($columns);

        $lines = array();
        foreach ($specs as $spec) {
            $lines[] = '    ' . $this->buildColumn($spec);
        }
        if ($primaryKey !== null) {
            $lines[] = '    PRIMARY KEY (' . $this->name($primaryKey) . ')';
        }

        // ENGINE and the table charset are MySQL storage parameters with no
        // PostgreSQL counterpart; the driver's empty $tableParameters drops them
        // for us, so no branch here is needed.
        $statements = array(sprintf(
            "CREATE TABLE %s (\n%s\n);",
            $this->name($table),
            implode(",\n", $lines)
        ));

        // Indexes are statements in their own right, not clauses.
        $indexes = isset($options['indexes']) ? $options['indexes'] : array();
        foreach ($indexes as $key => $indexOptions) {
            list($indexColumns, $indexOptions) = $this->normaliseIndexDeclaration($key, $indexOptions);
            $statements = array_merge(
                $statements,
                $this->addIndex($table, $indexColumns, $indexOptions)
            );
        }
        return $statements;
    }

    public function renameTable($from, $to)
    {
        return array(sprintf(
            'ALTER TABLE %s RENAME TO %s;',
            $this->name($from),
            $this->name($to)
        ));
    }

    // ----------------------------------------------------------------- table

    public function addColumn($table, $column, $type, array $options = array())
    {
        $this->notePositionDropped($column, $options);
        $spec = array_merge($options, array('name' => $column, 'type' => $type));
        return array(sprintf(
            'ALTER TABLE %s ADD %s%s;',
            $this->name($table),
            $this->buildColumn($spec),
            $this->primaryKeyClause($spec)
        ));
    }

    /**
     * The constraint is dropped by name, and the name is PostgreSQL's own
     * default for a primary key - "<table>_pkey" - which is what every table
     * the install baseline creates carries, and what ADD PRIMARY KEY gives a
     * table migrated in from elsewhere. A key someone named by hand is not
     * found, and the migration fails there with that name in the error
     * rather than guessing.
     */
    public function dropPrimaryKey($table)
    {
        return array(sprintf(
            'ALTER TABLE %s DROP CONSTRAINT %s;',
            $this->name($table),
            $this->name($table . '_pkey')
        ));
    }

    protected function renderChangeColumn($table, $column, $type, array $options)
    {
        $this->notePositionDropped($column, $options);
        return $this->alterColumn($table, $column, $type, $options);
    }

    protected function renderRenameColumn($table, $from, $to, $type, array $options)
    {
        $this->notePositionDropped($to, $options);
        $statements = array(sprintf(
            'ALTER TABLE %s RENAME COLUMN %s TO %s;',
            $this->name($table),
            $this->name($from),
            $this->name($to)
        ));
        // MySQL's CHANGE renames *and* redefines in one statement. Restating the
        // definition here keeps the two engines' end states identical, even when
        // the caller only meant to rename.
        return array_merge($statements, $this->alterColumn($table, $to, $type, $options));
    }

    public function addIndex($table, $columns, array $options = array())
    {
        if (!empty($options['fulltext'])) {
            throw new InvalidArgumentException(sprintf(
                'FULLTEXT has no PostgreSQL equivalent (index on %s.%s). Declare it with rawSql(), giving a MySQL FULLTEXT index and a PostgreSQL GIN index over to_tsvector().',
                $table,
                implode(', ', $this->columnList($columns))
            ));
        }
        if (isset($options['length'])) {
            $this->noteDroppedHint(sprintf(
                'Prefix length dropped from index %s on %s(%s): PostgreSQL indexes the whole value, so this index is not equivalent to its MySQL counterpart.',
                $this->indexName($table, $columns, $options),
                $table,
                implode(', ', $this->columnList($columns))
            ));
        }

        $parts = array();
        foreach ($this->columnList($columns) as $column) {
            $parts[] = $this->name($column);
        }

        return array(sprintf(
            'CREATE %sINDEX %s ON %s (%s);',
            empty($options['unique']) ? '' : 'UNIQUE ',
            $this->name($this->indexName($table, $columns, $options)),
            $this->name($table),
            implode(', ', $parts)
        ));
    }

    public function dropIndex($table, $columnsOrName)
    {
        return array(sprintf(
            'DROP INDEX %s;',
            $this->name($this->indexName($table, $columnsOrName))
        ));
    }

    /**
     * idx_<table>_<columns>, because index names share one namespace per schema.
     *
     * An explicit name is honoured but still prefixed, unless the caller already
     * prefixed it - so dropIndex() finds what addIndex() created whichever form
     * the migration used.
     */
    public function indexName($table, $columns, array $options = array())
    {
        $name = !empty($options['name'])
            ? $options['name']
            : implode('_', $this->columnList($columns));

        $prefix = 'idx_' . $table . '_';
        if (strpos($name, 'idx_') === 0) {
            return $name;
        }
        return $prefix . $name;
    }

    // --------------------------------------------------------------- helpers

    /**
     * Cake's Postgres map carries length modifiers PostgreSQL does not accept -
     * `biginteger` is declared as bigint with limit 20, which renders as
     * bigint(20) and is a syntax error. Callers hit the same thing by restating
     * a MySQL display width (`integer` length 11 -> integer(11)).
     *
     * So this is the one place a grammar corrects the driver's map rather than
     * adding to it: any entry whose rendered type does not take a modifier loses
     * its length. Author-supplied lengths are stripped alongside, in
     * normaliseColumn().
     *
     * @return array
     */
    protected function mergedColumns()
    {
        $merged = parent::mergedColumns();
        foreach ($merged as $type => $definition) {
            if (!isset($definition['name'])) {
                continue;
            }
            if ($this->acceptsLength($definition['name'])) {
                continue;
            }
            unset($merged[$type]['length'], $merged[$type]['limit']);
        }
        return $merged;
    }

    /**
     * Drop an author-supplied length for a type that cannot carry one.
     */
    protected function normaliseColumn(array $spec)
    {
        $spec = parent::normaliseColumn($spec);
        if (!isset($spec['type'])) {
            return $spec;
        }
        $merged = parent::mergedColumns();
        if (!isset($merged[$spec['type']]['name'])) {
            return $spec;
        }
        if (!$this->acceptsLength($merged[$spec['type']]['name'])) {
            unset($spec['length'], $spec['limit']);
        }
        return $spec;
    }

    /**
     * The SET/DROP triplet MySQL expresses as one MODIFY.
     *
     * Nullability and default are only touched when the caller actually said
     * something about them - restating a type should not silently drop a default
     * the column already had.
     *
     * @param string $table
     * @param string $column
     * @param string $type
     * @param array $options
     * @return array
     */
    private function alterColumn($table, $column, $type, array $options)
    {
        $spec = array_merge($options, array('name' => $column, 'type' => $type));
        $renderedType = $this->renderType($spec);
        $quotedColumn = $this->name($column);
        $quotedTable = $this->name($table);

        $statements = array(sprintf(
            'ALTER TABLE %s ALTER COLUMN %s TYPE %s USING %s::%s;',
            $quotedTable,
            $quotedColumn,
            $renderedType,
            $quotedColumn,
            $renderedType
        ));

        if (array_key_exists('null', $options)) {
            $statements[] = sprintf(
                'ALTER TABLE %s ALTER COLUMN %s %s NOT NULL;',
                $quotedTable,
                $quotedColumn,
                $options['null'] ? 'DROP' : 'SET'
            );
        }
        if (array_key_exists('default', $options)) {
            $statements[] = $options['default'] === null
                ? sprintf('ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT;', $quotedTable, $quotedColumn)
                : sprintf(
                    'ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s;',
                    $quotedTable,
                    $quotedColumn,
                    $this->value($options['default'], $type)
                );
        }
        return $statements;
    }

    /**
     * @param string $renderedType
     * @return bool
     */
    private function acceptsLength($renderedType)
    {
        return in_array(strtolower($renderedType), self::$lengthBearingTypes, true);
    }

    /**
     * @param string $column
     * @param array $options
     * @return void
     */
    private function notePositionDropped($column, array $options)
    {
        if (!empty($options['first'])) {
            $this->noteDroppedHint(sprintf(
                'Column position dropped for "%s" (FIRST): PostgreSQL appends columns. Cosmetic only.',
                $column
            ));
            return;
        }
        if (empty($options['after'])) {
            return;
        }
        $this->noteDroppedHint(sprintf(
            'Column position dropped for "%s" (AFTER "%s"): PostgreSQL appends columns. Cosmetic only.',
            $column,
            $options['after']
        ));
    }
}
