<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: events
 */
class Migration_20261016_180326_schema_v3_events extends TableMigration
{
    public $description = 'Schema modernisation: events';

    const TABLE = 'events';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'date' => array('type' => 'date', 'null' => false),
            'info' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'published' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'analysis' => array('type' => 'tinyinteger', 'null' => false),
            'attribute_count' => array('type' => 'integer', 'unsigned' => true, 'null' => true, 'default' => '0'),
            'orgc_id' => array('type' => 'biginteger', 'null' => false),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false),
            'proposal_email_lock' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'locked' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'threat_level_id' => array('type' => 'biginteger', 'null' => false),
            'publish_timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'sighting_timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'disable_correlation' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'extends_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => true,
                'default' => '',
                'collate' => Collation::ASCII,
            ),
            'protected' => array('type' => 'boolean', 'null' => true),
            'first_publication' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'extends_uuid' => array('column' => array('extends_uuid')),
            'first_publication' => array('column' => array('first_publication')),
            'idx_evt_acl' => array('column' => array('distribution', 'sharing_group_id')),
            'idx_evt_acl_flex' => array('column' => array('org_id', 'distribution', 'sharing_group_id', 'id')),
            'idx_evt_id_acl' => array('column' => array('id', 'org_id', 'distribution', 'sharing_group_id')),
            'idx_evt_ts_pub' => array('column' => array('timestamp', 'published')),
            'info' => array('column' => array('info'), 'length' => array('info' => 255)),
            'orgc_id' => array('column' => array('orgc_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array('org_id', 'sharing_group_id'),
    );
}
