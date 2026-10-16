<?php

App::uses('AbstractMigration', 'Migration');
App::uses('Collation', 'Migration');
App::uses('TableConverger', 'Migration');

/**
 * A migration that brings one table to a target definition.
 *
 *     class Migration_20261101_000012_schema_v3_events extends TableMigration
 *     {
 *         public $description = 'Schema modernisation: events';
 *
 *         const TABLE = 'events';
 *
 *         const TARGET = array(
 *             'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
 *             'columns' => array(...),
 *             'indexes' => array(...),
 *             'retired' => array('org_id', 'sharing_group_id'),
 *         );
 *     }
 *
 * The target is a frozen copy, as `Admin dumpSchemaTargets` writes it, never
 * a reference to a shared definition: a migration's meaning must not change
 * when a later one does. What the table already has is not declared again
 * (TableConverger), so a table at its target costs nothing and a run that
 * stopped resumes with what is left.
 */
abstract class TableMigration extends AbstractMigration
{
    /** The table this migration converges. */
    const TABLE = '';

    /** The table's complete definition; see TableConverger. */
    const TARGET = array();

    /**
     * Drop the table and create it empty at the target instead, for a table
     * whose rows are rebuilt after the upgrade.
     */
    const RECREATE = false;

    public function up(SchemaBuilder $schema)
    {
        if (static::RECREATE) {
            TableConverger::recreate($this->inspector(), $schema, static::TABLE, static::TARGET);
            return;
        }
        TableConverger::converge($this->inspector(), $schema, static::TABLE, static::TARGET);
    }
}
