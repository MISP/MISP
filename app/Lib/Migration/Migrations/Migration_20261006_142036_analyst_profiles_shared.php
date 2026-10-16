<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Let a site admin share an analyst profile with the instance
 */
class Migration_20261006_142036_analyst_profiles_shared extends AbstractMigration
{
    public $description = 'Let a site admin share an analyst profile with the instance';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * A shared profile is a site admin's own profile that every user may read,
     * fork and select. Only a site admin sets it, and only on a profile they
     * own personally.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('analyst_profiles', 'shared')) {
            return;
        }
        $schema->table('analyst_profiles')
            ->addColumn('shared', 'boolean', array(
                'null' => false, 'default' => 0, 'after' => 'default',
            ))
            ->addIndex('shared');
    }
}
