<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Create the analyst_profiles store
 */
class Migration_20260930_131926_analyst_profiles extends AbstractMigration
{
    public $description = 'Create the analyst_profiles store';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * The Analyst Profile store (prd/analyst-profile/02-store.md). Was legacy
     * update 160 on the personas branches; an instance that ran it has the
     * table and declares nothing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('analyst_profiles')) {
            return;
        }
        $schema->createTable('analyst_profiles', array(
            'id' => array('type' => 'primary_key'),
            'uuid' => array(
                'type' => 'string', 'length' => 40, 'null' => false,
                'charset' => 'ascii', 'collate' => 'ascii_general_ci',
            ),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false),
            'description' => array('type' => 'text', 'null' => true, 'default' => null),
            'user_id' => array('type' => 'integer', 'null' => true, 'default' => null),
            'org_id' => array('type' => 'integer', 'null' => true, 'default' => null),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => 0),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => 1),
            'version' => array('type' => 'integer', 'null' => false, 'default' => 1),
            'revision' => array('type' => 'integer', 'null' => false, 'default' => 1),
            'parameters' => array('type' => 'longtext', 'null' => true, 'default' => null),
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
        ), array(
            'indexes' => array(
                'uuid' => array('unique' => true),
                'name' => array(),
                'user_id' => array(),
                'org_id' => array(),
                'default' => array(),
                'enabled' => array(),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
            'collate' => 'utf8mb4_unicode_ci',
        ));
    }
}
