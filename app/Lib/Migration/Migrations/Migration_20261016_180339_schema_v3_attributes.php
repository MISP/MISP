<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: attributes
 */
class Migration_20261016_180339_schema_v3_attributes extends TableMigration
{
    public $description = 'Schema modernisation: attributes';

    const TABLE = 'attributes';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'object_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'object_relation' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'collate' => Collation::BIN,
            ),
            'category' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'type' => array('type' => 'string', 'length' => 100, 'null' => false, 'collate' => Collation::CI),
            'value1_id' => array('type' => 'biginteger', 'null' => true),
            'value2_id' => array('type' => 'biginteger', 'null' => true),
            'to_ids' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'created' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'disable_correlation' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'first_seen' => array('type' => 'biginteger', 'null' => true),
            'last_seen' => array('type' => 'biginteger', 'null' => true),
        ),
        'indexes' => array(
            'category' => array('column' => array('category')),
            'created' => array('column' => array('created')),
            'first_seen' => array('column' => array('first_seen')),
            'idx_attr_acl_primary' => array(
                'column' => array('deleted', 'distribution', 'sharing_group_id', 'event_id'),
            ),
            'idx_attr_acl_type' => array(
                'column' => array('event_id', 'distribution', 'sharing_group_id', 'deleted', 'type'),
            ),
            'idx_attr_deleted_ts' => array('column' => array('deleted', 'timestamp', 'id')),
            'idx_attr_obj_dist' => array('column' => array('object_id', 'distribution')),
            'idx_attr_objrel_acl' => array(
                'column' => array('object_relation', 'event_id', 'distribution', 'sharing_group_id', 'deleted'),
            ),
            'idx_attr_search_core' => array(
                'column' => array('type', 'to_ids', 'deleted', 'distribution', 'sharing_group_id', 'event_id'),
            ),
            'idx_attr_ts_acl' => array(
                'column' => array('timestamp', 'deleted', 'distribution', 'sharing_group_id', 'event_id'),
            ),
            'idx_attr_type_event' => array('column' => array('type', 'event_id')),
            'idx_attr_type_id' => array('column' => array('type', 'id')),
            'idx_attr_vid_combo' => array('column' => array('value1_id', 'value2_id')),
            'idx_event_deleted_object' => array('column' => array('event_id', 'deleted', 'object_id')),
            'idx_vid1_source' => array(
                'column' => array('event_id', 'value1_id', 'deleted', 'disable_correlation', 'type', 'id'),
            ),
            'idx_vid1_target' => array(
                'column' => array('value1_id', 'event_id', 'deleted', 'disable_correlation', 'type', 'id'),
            ),
            'idx_vid2_source' => array(
                'column' => array('event_id', 'value2_id', 'deleted', 'disable_correlation', 'type', 'id'),
            ),
            'idx_vid2_target' => array(
                'column' => array('value2_id', 'event_id', 'deleted', 'disable_correlation', 'type', 'id'),
            ),
            'last_seen' => array('column' => array('last_seen')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(
            'deleted',
            'event_id',
            'idx_attr_evt_dist',
            'idx_attr_type_ts',
            'object_id',
            'object_relation',
            'timestamp',
            'type',
        ),
    );
}
