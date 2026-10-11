<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add an API key to SightingDB connections
 */
class Migration_20261011_153000_sightingdbs_api_key extends AbstractMigration
{
    public $description = 'Add an API key to SightingDB connections';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * sightingdbs.api_key is sent as the Authorization header, so MISP can
     * query a SightingDB that runs with authenticate = true. Nullable: a
     * connection without one keeps querying unauthenticated, as before.
     * Named api_key so the audit log masks it.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('sightingdbs', 'api_key')) {
            return;
        }
        $schema->table('sightingdbs')->addColumn('api_key', 'string', array(
            'length' => 255,
            'null' => true,
            'default' => null,
            'after' => 'namespace',
        ));
    }
}
