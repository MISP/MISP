<?php

App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('OfflineConnection', 'Migration/Grammar');

/**
 * MySQL/MariaDB rendering.
 *
 * The easy engine, because it is the one the historic corpus was written
 * against - every hint the DSL offers has a native spelling here, so nothing is
 * ever dropped. takeDroppedHints() only says which server an offline rendering
 * resolved a collation token for.
 *
 * Charset, collate, comment, unsigned, ENGINE and the table charset all arrive
 * from Cake's own $fieldParameters/$tableParameters. This class adds what Cake
 * has no notion of: positional `after`, prefix-length index parts, FULLTEXT,
 * the mediumtext/longtext/varbinary types the MISP schema uses, and collation
 * tokens, resolved for the server the datasource reports.
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

        $options = $this->resolveRowFormat($this->resolveCollation($options));
        $tableParameters = $this->db->buildTableParameters($options);
        if (isset($options['row_format'])) {
            $tableParameters[] = 'ROW_FORMAT=' . $options['row_format'];
        }
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

    protected function addColumnParts($table, $column, $type, array $options)
    {
        $spec = array_merge($options, array('name' => $column, 'type' => $type));
        return array($this->clause(sprintf(
            'ADD %s%s%s',
            $this->buildColumn($spec),
            $this->primaryKeyClause($spec),
            $this->positionClause($options)
        )));
    }

    protected function changeColumnParts($table, $column, $type, array $options)
    {
        $spec = array_merge($options, array('name' => $column, 'type' => $type));
        return array($this->clause(sprintf(
            'MODIFY %s%s',
            $this->buildColumn($spec),
            $this->positionClause($options)
        )));
    }

    protected function renameColumnParts($table, $from, $to, $type, array $options)
    {
        // CHANGE restates the whole definition, which is why the DSL asks for the
        // type on a rename even though a rename alone does not obviously need one.
        $spec = array_merge($options, array('name' => $to, 'type' => $type));
        return array($this->clause(sprintf(
            'CHANGE %s %s%s',
            $this->name($from),
            $this->buildColumn($spec),
            $this->positionClause($options)
        )));
    }

    protected function dropPrimaryKeyParts($table)
    {
        return array($this->clause('DROP PRIMARY KEY'));
    }

    protected function addIndexParts($table, $columns, array $options)
    {
        return array($this->clause('ADD ' . $this->indexClause($table, $columns, $options)));
    }

    protected function dropIndexParts($table, $columnsOrName)
    {
        return array($this->clause(
            'DROP INDEX ' . $this->name($this->indexName($table, $columnsOrName))
        ));
    }

    /**
     * One clause per option, the default charset and collation together.
     */
    protected function changeOptionsParts($table, array $options)
    {
        $options = $this->tableOptions($options);
        $parts = array();
        if (isset($options['engine'])) {
            $parts[] = $this->clause('ENGINE=' . $options['engine']);
        }
        if (isset($options['row_format'])) {
            $parts[] = $this->clause('ROW_FORMAT=' . $options['row_format']);
        }
        $default = array();
        if (isset($options['charset'])) {
            $default[] = 'DEFAULT CHARSET=' . $options['charset'];
        }
        if (isset($options['collate'])) {
            $default[] = 'COLLATE=' . $options['collate'];
        }
        if (!empty($default)) {
            $parts[] = $this->clause(implode(' ', $default));
        }
        return $parts;
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
     * Charset before collate, the order buildTableParameters() renders them in.
     */
    protected function collationFor($token, array $options)
    {
        $version = $this->db->getVersion();
        $resolved = Collation::forServer($token, $version);
        unset($options['charset'], $options['collate']);
        if ($this->db->getConnection() instanceof OfflineConnection) {
            $this->noteAssumedServer($token, $version);
        }
        return $options + $resolved;
    }

    /**
     * With no server to ask, say what a token was resolved for whenever the
     * other family names it differently.
     *
     * @param string $token
     * @param string $version
     * @return void
     */
    private function noteAssumedServer($token, $version)
    {
        $byFamily = Collation::byFamily($token);
        if (count(array_unique($byFamily)) === 1) {
            return;
        }
        list($family, $release) = Collation::server($version);
        $others = array();
        foreach ($byFamily as $other => $collation) {
            if ($other !== $family) {
                $others[] = sprintf('%s takes %s', $other, $collation);
            }
        }
        $note = sprintf(
            'No MySQL-family server is connected, so %s is rendered for %s %s as %s; %s.',
            $token,
            $family,
            $release,
            $byFamily[$family],
            implode(', ', $others)
        );
        if (!in_array($note, $this->droppedHints, true)) {
            $this->noteDroppedHint($note);
        }
    }

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
