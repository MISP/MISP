<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: shadow_attributes
 */
class Migration_20261016_180317_schema_v3_shadow_attributes extends TableMigration
{
    public $description = 'Schema modernisation: shadow_attributes';

    const TABLE = 'shadow_attributes';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'old_id' => array('type' => 'biginteger', 'null' => true, 'default' => '0'),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'type' => array('type' => 'string', 'length' => 100, 'null' => false, 'collate' => Collation::CI),
            'category' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'to_ids' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'value1_id' => array('type' => 'biginteger', 'null' => true),
            'value2_id' => array('type' => 'biginteger', 'null' => true),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'email' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'event_org_id' => array('type' => 'biginteger', 'null' => false),
            'comment' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'event_uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'proposal_to_delete' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'disable_correlation' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'first_seen' => array('type' => 'biginteger', 'null' => true),
            'last_seen' => array('type' => 'biginteger', 'null' => true),
        ),
        'indexes' => array(
            'category' => array('column' => array('category')),
            'event_id' => array('column' => array('event_id')),
            'event_org_id' => array('column' => array('event_org_id')),
            'event_uuid' => array('column' => array('event_uuid')),
            'first_seen' => array('column' => array('first_seen')),
            'last_seen' => array('column' => array('last_seen')),
            'old_id' => array('column' => array('old_id')),
            'type' => array('column' => array('type')),
            'uuid' => array('column' => array('uuid')),
            'value1_id' => array('column' => array('value1_id')),
            'value2_id' => array('column' => array('value2_id')),
        ),
        'retired' => array(),
    );
}
