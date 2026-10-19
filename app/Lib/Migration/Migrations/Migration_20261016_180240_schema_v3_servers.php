<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: servers
 */
class Migration_20261016_180240_schema_v3_servers extends TableMigration
{
    public $description = 'Schema modernisation: servers';

    const TABLE = 'servers';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'url' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'authkey' => array('type' => 'varbinary', 'length' => 255, 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'push' => array('type' => 'boolean', 'null' => false),
            'pull' => array('type' => 'boolean', 'null' => false),
            'push_sightings' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'push_galaxy_clusters' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'push_analyst_data' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'pull_analyst_data' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'pull_galaxy_clusters' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'push_collections' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'pull_collections' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'lastpulledid' => array('type' => 'biginteger', 'null' => true),
            'lastpushedid' => array('type' => 'biginteger', 'null' => true),
            'organization' => array('type' => 'string', 'length' => 10, 'null' => true, 'collate' => Collation::BIN),
            'remote_org_id' => array('type' => 'biginteger', 'null' => false),
            'publish_without_email' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'unpublish_event' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'self_signed' => array('type' => 'boolean', 'null' => false),
            'pull_rules' => array('type' => 'mediumtext', 'null' => false, 'collate' => Collation::BIN),
            'push_rules' => array('type' => 'mediumtext', 'null' => false, 'collate' => Collation::BIN),
            'cert_file' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::BIN),
            'client_cert_file' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'collate' => Collation::BIN,
            ),
            'internal' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'skip_proxy' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'remove_missing_tags' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'caching_enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'priority' => array('type' => 'integer', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id')),
            'priority' => array('column' => array('priority')),
            'remote_org_id' => array('column' => array('remote_org_id')),
        ),
        'retired' => array(),
    );
}
