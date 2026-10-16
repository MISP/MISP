<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Create the value_enrichment_runs store
 */
class Migration_20260930_131927_value_enrichment_runs extends AbstractMigration
{
    public $description = 'Create the value_enrichment_runs store';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * The enrichment run store (prd/analyst-profile/13-auto-run.md §4): one
     * row per (org, value, module, type), upserted by every run. Was legacy
     * update 161 on the personas branches; an instance that ran it has the
     * table and declares nothing.
     *
     * `value_hash` is sha256 of the value as the page received it, the
     * identity the page's Redis keys already use.
     *
     * `result` holds a compressed payload that can pass 64 KB, which is all a
     * MySQL BLOB takes and all the DSL's binary renders as there, so MySQL
     * widens it to LONGBLOB. PostgreSQL's bytea is unbounded already.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('value_enrichment_runs')) {
            return;
        }
        $schema->createTable('value_enrichment_runs', array(
            'id' => array('type' => 'primary_key'),
            'org_id' => array('type' => 'integer', 'null' => false),
            'value_hash' => array(
                'type' => 'string', 'length' => 64, 'null' => false,
                'charset' => 'ascii', 'collate' => 'ascii_general_ci',
            ),
            'value' => array('type' => 'text', 'null' => true, 'default' => null),
            'module' => array('type' => 'string', 'length' => 100, 'null' => false),
            'type' => array('type' => 'string', 'length' => 100, 'null' => false),
            'state' => array('type' => 'string', 'length' => 32, 'null' => false),
            'user_id' => array('type' => 'integer', 'null' => true, 'default' => null),
            'last_run' => array('type' => 'integer', 'null' => false, 'default' => 0),
            'took' => array('type' => 'integer', 'null' => false, 'default' => 0),
            'total' => array('type' => 'integer', 'null' => false, 'default' => 0),
            'shown' => array('type' => 'integer', 'null' => false, 'default' => 0),
            'capped' => array('type' => 'boolean', 'null' => false, 'default' => 0),
            'message' => array('type' => 'text', 'null' => true, 'default' => null),
            'result' => array('type' => 'binary', 'null' => true, 'default' => null),
        ), array(
            'indexes' => array(
                'run' => array(
                    'column' => array('org_id', 'value_hash', 'module', 'type'),
                    'unique' => true,
                ),
                'last_run' => array(),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
            'collate' => 'utf8mb4_unicode_ci',
        ));
        $schema->rawSql(array(
            'mysql' => 'ALTER TABLE `value_enrichment_runs` MODIFY `result` LONGBLOB DEFAULT NULL;',
            'pgsql' => array(),
        ));
    }
}
