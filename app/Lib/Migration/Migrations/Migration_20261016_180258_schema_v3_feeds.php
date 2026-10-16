<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: feeds
 */
class Migration_20261016_180258_schema_v3_feeds extends TableMigration
{
    public $description = 'Schema modernisation: feeds';

    const TABLE = 'feeds';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'provider' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'url' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'rules' => array('type' => 'mediumtext', 'null' => true, 'collate' => Collation::BIN),
            'enabled' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'tag_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'default' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'source_format' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => 'misp',
                'collate' => Collation::BIN,
            ),
            'fixed_event' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'delta_merge' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'event_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'publish' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'override_ids' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'settings' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'input_source' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => 'network',
                'collate' => Collation::BIN,
            ),
            'delete_local_file' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'lookup_visible' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'headers' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'caching_enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'force_to_ids' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'orgc_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'tag_collection_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'lock_events' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'input_source' => array('column' => array('input_source')),
            'orgc_id' => array('column' => array('orgc_id')),
        ),
        'retired' => array(),
    );
}
