<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Create analyst_profile_selections, an organisation's choice of Analyst Profile
 */
class Migration_20260930_131929_analyst_profile_selections extends AbstractMigration
{
    public $description = 'Create analyst_profile_selections, an organisation\'s choice of Analyst Profile';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * An organisation's choice of Analyst Profile (prd/personas/03-profiles.md
     * §5, D45). A user keeps theirs in `user_settings` and the instance in
     * `ValueIntelligence_instance_profile`; nothing held a per-organisation
     * setting. Three columns rather than an empty-parameters row in
     * `analyst_profiles`, so a selection is never mistaken for a profile.
     * `org_id` is unique because each scope has one answer. Was legacy update
     * 163 on the personas branches.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('analyst_profile_selections')) {
            return;
        }
        $schema->createTable('analyst_profile_selections', array(
            'id' => array('type' => 'primary_key'),
            'org_id' => array('type' => 'integer', 'null' => false),
            'uuid' => array(
                'type' => 'string', 'length' => 40, 'null' => false,
                'charset' => 'ascii', 'collate' => 'ascii_general_ci',
            ),
            'modified' => array('type' => 'datetime', 'null' => false),
        ), array(
            'indexes' => array(
                'org_id' => array('unique' => true),
                'uuid' => array(),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
            'collate' => 'utf8mb4_unicode_ci',
        ));
    }
}
