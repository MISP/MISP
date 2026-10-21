<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Index galaxy cluster relations by the UUID of the cluster they point at
 */
class Migration_20261021_091751_index_relation_referenced_uuid extends AbstractMigration
{
    public $description = 'Index galaxy cluster relations by the UUID of the cluster they point at';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * Inbound relations are found by the UUID they name: the cached target id
     * goes stale when a galaxy update replaces the cluster.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasIndex('galaxy_cluster_relations', 'referenced_galaxy_cluster_uuid')) {
            return;
        }
        $schema->table('galaxy_cluster_relations')
            ->addIndex('referenced_galaxy_cluster_uuid');
    }
}
