<?php

/**
 * The chainable half of the DSL: everything scoped to one table.
 *
 * Handed out by SchemaBuilder::table() and bound to that table name. It holds no
 * state of its own - each call pushes an operation straight back into the
 * SchemaBuilder that created it, which is what keeps declaration order intact
 * when a migration interleaves table-scoped and schema-scoped work.
 *
 * @see SchemaBuilder
 */
class SchemaTableBuilder
{
    /**
     * @var SchemaBuilder
     */
    private $schema;

    /**
     * @var string
     */
    private $table;

    public function __construct(SchemaBuilder $schema, $table)
    {
        $this->schema = $schema;
        $this->table = $table;
    }

    /**
     * @param string $column
     * @param string $type One of the DSL's column types. 'primary_key' adds an
     *   auto-increment integer that is the table's key - the table must not
     *   have one already; see dropPrimaryKey().
     * @param array $options 'null', 'default', 'length', 'unsigned', 'charset',
     *   'collate', 'comment', 'after', 'first'.
     * @return $this
     */
    public function addColumn($column, $type, array $options = array())
    {
        return $this->push('addColumn', array($this->table, $column, $type, $options));
    }

    /**
     * Redefines a column. 'null' and 'default' are both required: MySQL's MODIFY
     * replaces the whole definition and drops what is left unsaid, while
     * PostgreSQL's ALTER COLUMN ... TYPE leaves it in place, so anything
     * unstated ends up different on the two engines. Pass 'default' => null when
     * the column has no default.
     *
     * @param string $column
     * @param string $type
     * @param array $options Must include 'null' and 'default'.
     * @return $this
     */
    public function changeColumn($column, $type, array $options = array())
    {
        return $this->push('changeColumn', array($this->table, $column, $type, $options));
    }

    /**
     * The type is required, not optional: MySQL's CHANGE restates the whole
     * definition, and PostgreSQL needs it to keep the two engines' end states
     * the same. 'null' and 'default' are required for the same reason as in
     * changeColumn().
     *
     * @param string $from
     * @param string $to
     * @param string $type
     * @param array $options Must include 'null' and 'default'.
     * @return $this
     */
    public function renameColumn($from, $to, $type, array $options = array())
    {
        return $this->push('renameColumn', array($this->table, $from, $to, $type, $options));
    }

    /**
     * @param string $column
     * @return $this
     */
    public function dropColumn($column)
    {
        return $this->push('dropColumn', array($this->table, $column));
    }

    /**
     * @param string|array $columns One column, or an ordered list for a composite index.
     * @param array $options 'unique', 'name', 'length' (MySQL prefix index),
     *   'fulltext' (MySQL only - PostgreSQL rejects it, use rawSql()).
     * @return $this
     */
    public function addIndex($columns, array $options = array())
    {
        return $this->push('addIndex', array($this->table, $columns, $options));
    }

    /**
     * @param string|array $columnsOrName The column set, or the index's own name.
     * @return $this
     */
    public function dropIndex($columnsOrName)
    {
        return $this->push('dropIndex', array($this->table, $columnsOrName));
    }

    /**
     * Drop the table's primary key constraint, keeping its columns. The usual
     * reason is that an id is about to take its place: add a unique index over
     * the old key column first, so nothing is unconstrained in between.
     *
     * @return $this
     */
    public function dropPrimaryKey()
    {
        return $this->push('dropPrimaryKey', array($this->table));
    }

    /**
     * @param string $operation
     * @param array $arguments
     * @return $this
     */
    private function push($operation, array $arguments)
    {
        $this->schema->addOperation($operation, $arguments);
        return $this;
    }
}
