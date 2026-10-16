<?php

App::uses('AbstractMigration', 'Migration');
App::uses('Collation', 'Migration');
App::uses('TableConverger', 'Migration');
App::uses('TablePreflight', 'Migration');

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
 *
 * The rebuild can run for hours, so the migration is offline: the manager
 * does not start it from the web or on a live instance, and beforeUp() defers
 * outside the CLI as a backstop. Its statements run under session settings
 * that let the server choose each ALTER's algorithm (TableConverger::session()).
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

    public $offline = true;

    /** @var array|null What beforeUp() checked, for up() to declare. */
    private $plan;

    /** @var array|null The checked plan's forecast, for forecast() after up(). */
    private $expected;

    /** @var array Other sessions found busy when beforeUp() ran. */
    private $busy = array();

    public function beforeUp()
    {
        $this->plan = null;
        $this->expected = null;
        $this->busy = array();
        if (PHP_SAPI !== 'cli') {
            $this->defer('Schema modernisation runs offline: Console/cake Admin live 0; Console/cake Admin migrationApply');
        }
        $checked = TableConverger::preflight($this->inspector(), static::TABLE, static::TARGET, static::RECREATE);
        if (!empty($checked['defer'])) {
            $this->defer(implode(PHP_EOL, $checked['defer']));
        }
        $this->plan = $checked['plan'];
        $this->expected = isset($this->plan['forecast']) ? $this->plan['forecast'] : null;
        $this->busy = $this->inspector()->otherActiveSessions();
        return true;
    }

    public function forecast()
    {
        $lines = array();
        $forecast = $this->expected;
        if ($forecast !== null) {
            $kinds = array(
                'copy' => 'copies every row into a new table; the table cannot be written meanwhile',
                'inplace' => 'rebuilds the table in place',
                'indexes' => 'builds new indexes',
            );
            $lines[] = sprintf(
                '%s: about %d rows, %s with its indexes; %s; needs about %s of free disk',
                static::TABLE,
                $forecast['rows'],
                TablePreflight::bytes($forecast['bytes']),
                $kinds[$forecast['kind']],
                TablePreflight::bytes($forecast['need'])
            );
            $inspector = $this->inspector();
            if ($inspector->flavour() === AbstractGrammar::FLAVOUR_MYSQL) {
                $lines[] = $inspector->isMariaDb()
                    ? 'Watch it: SHOW FULL PROCESSLIST, the Progress column of the ALTER'
                    : 'Watch it: performance_schema.events_stages_current (the stage/innodb/alter table % instruments)';
            }
        }
        if (!empty($this->busy)) {
            $lines[] = sprintf(
                'Warning: %d other session(s) are running statements on this database; the rebuild waits for their locks, up to %d s',
                count($this->busy),
                TableConverger::LOCK_WAIT
            );
        }
        return $lines;
    }

    public function up(SchemaBuilder $schema)
    {
        if ($this->plan !== null) {
            $plan = $this->plan;
            $this->plan = null;
            TableConverger::emit($schema, $plan, TableConverger::session($this->inspector()));
            return;
        }
        $session = TableConverger::session($this->inspector());
        if (static::RECREATE) {
            TableConverger::recreate($this->inspector(), $schema, static::TABLE, static::TARGET, $session);
            return;
        }
        TableConverger::converge($this->inspector(), $schema, static::TABLE, static::TARGET, $session);
    }
}
