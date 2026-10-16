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
 *
 * beforeUp() checks the server and the rows first (TablePreflight) and defers
 * on anything the rebuild could not get past; up() then declares the plan it
 * checked, since a check can change it. A subclass that puts rows right in
 * beforeUp() does so before calling the parent's. A dry run plans without
 * the checks.
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

    /** @var array|null What beforeUp() checked, for up() to declare. */
    private $plan;

    public function beforeUp()
    {
        $this->plan = null;
        $checked = TableConverger::preflight($this->inspector(), static::TABLE, static::TARGET, static::RECREATE);
        if (!empty($checked['defer'])) {
            $this->defer(implode(PHP_EOL, $checked['defer']));
        }
        $this->plan = $checked['plan'];
        return true;
    }

    public function up(SchemaBuilder $schema)
    {
        if ($this->plan !== null) {
            $plan = $this->plan;
            $this->plan = null;
            TableConverger::emit($schema, $plan);
            return;
        }
        if (static::RECREATE) {
            TableConverger::recreate($this->inspector(), $schema, static::TABLE, static::TARGET);
            return;
        }
        TableConverger::converge($this->inspector(), $schema, static::TABLE, static::TARGET);
    }
}
