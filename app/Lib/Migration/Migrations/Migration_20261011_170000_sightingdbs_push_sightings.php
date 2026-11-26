<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Let SightingDB connections receive the sightings recorded in MISP
 */
class Migration_20261011_170000_sightingdbs_push_sightings extends AbstractMigration
{
    public $description = 'Let SightingDB connections receive the sightings recorded in MISP';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * sightingdbs.push_sightings: when set, every sighting recorded in MISP is
     * also written to that SightingDB, as the SHA-256 of the attribute value -
     * the same form MISP looks values up in, so what is pushed is what the
     * lookups find. Off by default: an existing connection keeps being read
     * from only.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('sightingdbs', 'push_sightings')) {
            return;
        }
        $schema->table('sightingdbs')->addColumn('push_sightings', 'boolean', array(
            'null' => false,
            'default' => 0,
            'after' => 'enabled',
        ));
    }
}
