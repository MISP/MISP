<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Give SightingDB connections a namespace for false-positives
 */
class Migration_20261011_180000_sightingdbs_false_positive_namespace extends AbstractMigration
{
    public $description = 'Give SightingDB connections a namespace for false-positives';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * sightingdbs.false_positive_namespace: SightingDB only counts, so MISP's
     * false-positives are kept apart from its sightings in a namespace of their
     * own - pushed there, and read back from there into MISP's false-positive
     * count. Empty leaves false-positives out, as before.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('sightingdbs', 'false_positive_namespace')) {
            return;
        }
        $schema->table('sightingdbs')->addColumn('false_positive_namespace', 'string', array(
            'length' => 255,
            'null' => true,
            'default' => null,
            'after' => 'namespace',
        ));
    }
}
