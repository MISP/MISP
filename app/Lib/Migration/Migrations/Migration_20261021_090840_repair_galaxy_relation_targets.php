<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Point galaxy cluster relations at the clusters their UUID names
 */
class Migration_20261021_090840_repair_galaxy_relation_targets extends AbstractMigration
{
    public $description = 'Point galaxy cluster relations at the clusters their UUID names';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * No schema change: the repair is data only.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }

    /**
     * Relations other galaxies hold towards a cluster a galaxy update replaced
     * still name the deleted row's id; re-point them, once, on instances that
     * updated their galaxies before the update learnt to.
     *
     * @return bool
     */
    public function afterUp()
    {
        ClassRegistry::init('GalaxyCluster')->generateMissingRelations();
        return true;
    }
}
