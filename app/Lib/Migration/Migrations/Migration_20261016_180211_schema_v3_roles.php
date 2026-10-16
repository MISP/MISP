<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: roles
 */
class Migration_20261016_180211_schema_v3_roles extends TableMigration
{
    public $description = 'Schema modernisation: roles';

    const TABLE = 'roles';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 100, 'null' => false, 'collate' => Collation::BIN),
            'created' => array('type' => 'datetime', 'null' => true),
            'modified' => array('type' => 'datetime', 'null' => true),
            'perm_add' => array('type' => 'boolean', 'null' => true),
            'perm_modify' => array('type' => 'boolean', 'null' => true),
            'perm_modify_org' => array('type' => 'boolean', 'null' => true),
            'perm_publish' => array('type' => 'boolean', 'null' => true),
            'perm_delegate' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_sync' => array('type' => 'boolean', 'null' => true),
            'perm_admin' => array('type' => 'boolean', 'null' => true),
            'perm_audit' => array('type' => 'boolean', 'null' => true),
            'perm_full' => array('type' => 'boolean', 'null' => true),
            'perm_auth' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_site_admin' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_regexp_access' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_tagger' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_template' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_sharing_group' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_tag_editor' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_sighting' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_object_template' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'default_role' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'memory_limit' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'max_execution_time' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'restricted_to_site_admin' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_publish_zmq' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_publish_kafka' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_decaying' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'enforce_rate_limit' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'rate_limit_count' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'perm_galaxy_editor' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_warninglist' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_view_feed_correlations' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_analyst_data' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_skip_otp' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_server_sign' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_sync_internal' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'perm_sync_authoritative' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'restsearch_limit_result' => array('type' => 'integer', 'null' => true, 'default' => '0'),
            'perm_ai_tools' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
