<?php

App::uses('AbstractGrammar', 'Migration/Grammar');

/**
 * MySQL/MariaDB rendering.
 *
 * The easy engine, because it is the one the historic corpus was written
 * against - every hint the DSL offers has a native spelling here, so nothing is
 * ever dropped and takeDroppedHints() stays empty.
 *
 * Charset, collate, comment, unsigned, ENGINE and the table charset all arrive
 * from Cake's own $fieldParameters/$tableParameters. This class adds what Cake
 * has no notion of: positional `after`, prefix-length index parts, FULLTEXT, and
 * the mediumtext/longtext/varbinary types the MISP schema uses.
 *
 * Statement shapes follow the ones the legacy corpus and AppModel::__addIndex()
 * already emit (ADD INDEX / DROP INDEX rather than Cake's ADD KEY), so a reader
 * comparing an old migration against a new one sees the same SQL.
 */
class MysqlGrammar extends AbstractGrammar
{
    /**
     * Types the MISP schema uses that Cake's Mysql map does not define.
     *
     * @var array
     */
    protected $extraColumns = array(
        'mediumtext' => array('name' => 'mediumtext'),
        'longtext' => array('name' => 'longtext'),
        'varbinary' => array('name' => 'varbinary'),
    );

    public function flavour()
    {
        return self::FLAVOUR_MYSQL;
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
        $indexes = isset($options['indexes']) ? $options['indexes'] : array();
        foreach ($indexes as $key => $indexOptions) {
            list($indexColumns, $indexOptions) = $this->normaliseIndexDeclaration($key, $indexOptions);
            $lines[] = '    ' . $this->indexClause($table, $indexColumns, $indexOptions);
        }

        $tableParameters = $this->db->buildTableParameters($options);
        $suffix = empty($tableParameters) ? '' : ' ' . implode(' ', $tableParameters);

        return array(sprintf(
            "CREATE TABLE %s (\n%s\n)%s;",
            $this->name($table),
            implode(",\n", $lines),
            $suffix
        ));
    }

    public function renameTable($from, $to)
    {
        return array(sprintf(
            'RENAME TABLE %s TO %s;',
            $this->name($from),
            $this->name($to)
        ));
    }

    // ----------------------------------------------------------------- table

    public function addColumn($table, $column, $type, array $options = array())
    {
        $spec = array_merge($options, array('name' => $column, 'type' => $type));
        return array(sprintf(
            'ALTER TABLE %s ADD %s%s%s;',
            $this->name($table),
            $this->buildColumn($spec),
            $this->primaryKeyClause($spec),
            $this->positionClause($options)
        ));
    }

    public function dropPrimaryKey($table)
    {
        return array(sprintf('ALTER TABLE %s DROP PRIMARY KEY;', $this->name($table)));
    }

    protected function renderChangeColumn($table, $column, $type, array $options)
    {
        $spec = array_merge($options, array('name' => $column, 'type' => $type));
        return array(sprintf(
            'ALTER TABLE %s MODIFY %s%s;',
            $this->name($table),
            $this->buildColumn($spec),
            $this->positionClause($options)
        ));
    }

    protected function renderRenameColumn($table, $from, $to, $type, array $options)
    {
        // CHANGE restates the whole definition, which is why the DSL asks for the
        // type on a rename even though a rename alone does not obviously need one.
        $spec = array_merge($options, array('name' => $to, 'type' => $type));
        return array(sprintf(
            'ALTER TABLE %s CHANGE %s %s%s;',
            $this->name($table),
            $this->name($from),
            $this->buildColumn($spec),
            $this->positionClause($options)
        ));
    }

    public function addIndex($table, $columns, array $options = array())
    {
        return array(sprintf(
            'ALTER TABLE %s ADD %s;',
            $this->name($table),
            $this->indexClause($table, $columns, $options)
        ));
    }

    public function dropIndex($table, $columnsOrName)
    {
        return array(sprintf(
            'ALTER TABLE %s DROP INDEX %s;',
            $this->name($table),
            $this->name($this->indexName($table, $columnsOrName))
        ));
    }

    /**
     * An index is named after its column, or after its columns joined with an
     * underscore - the same convention AppModel::__addIndex() has always used.
     */
    public function indexName($table, $columns, array $options = array())
    {
        if (!empty($options['name'])) {
            return $options['name'];
        }
        return implode('_', $this->columnList($columns));
    }

    // --------------------------------------------------------------- helpers

    /**
     * The shared part of ADD INDEX and the create-table index clause.
     *
     * @param string $table
     * @param string|array $columns
     * @param array $options
     * @return string
     */
    private function indexClause($table, $columns, array $options = array())
    {
        $keyword = 'INDEX';
        if (!empty($options['fulltext'])) {
            $keyword = 'FULLTEXT INDEX';
        } elseif (!empty($options['unique'])) {
            $keyword = 'UNIQUE INDEX';
        }

        $parts = array();
        foreach ($this->columnList($columns) as $column) {
            $parts[] = $this->name($column) . $this->prefixLength($column, $options);
        }

        return sprintf(
            '%s %s (%s)',
            $keyword,
            $this->name($this->indexName($table, $columns, $options)),
            implode(', ', $parts)
        );
    }

    /**
     * The (16) in `meta-category`(16).
     *
     * `length` is either a bare number - which applies to a single-column index -
     * or a column => length map for a composite one.
     *
     * @param string $column
     * @param array $options
     * @return string
     */
    private function prefixLength($column, array $options)
    {
        if (!isset($options['length'])) {
            return '';
        }
        $length = $options['length'];
        if (is_array($length)) {
            return isset($length[$column]) ? '(' . (int)$length[$column] . ')' : '';
        }
        return '(' . (int)$length . ')';
    }

    /**
     * @param array $options
     * @return string
     */
    private function positionClause(array $options)
    {
        if (!empty($options['first'])) {
            return ' FIRST';
        }
        if (empty($options['after'])) {
            return '';
        }
        return ' AFTER ' . $this->name($options['after']);
    }
}
