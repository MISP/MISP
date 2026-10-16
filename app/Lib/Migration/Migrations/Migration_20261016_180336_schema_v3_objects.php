<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: objects
 */
class Migration_20261016_180336_schema_v3_objects extends TableMigration
{
    public $description = 'Schema modernisation: objects';

    const TABLE = 'objects';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'meta-category' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'template_uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'template_version' => array('type' => 'integer', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
            'comment' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'first_seen' => array('type' => 'biginteger', 'null' => true),
            'last_seen' => array('type' => 'biginteger', 'null' => true),
        ),
        'indexes' => array(
            'first_seen' => array('column' => array('first_seen')),
            'idx_event_deleted_name' => array('column' => array('event_id', 'deleted', 'name')),
            'idx_obj_acl' => array('column' => array('event_id', 'distribution', 'sharing_group_id', 'deleted')),
            'idx_obj_id_acl' => array('column' => array('id', 'event_id', 'distribution')),
            'idx_obj_meta' => array('column' => array('meta-category', 'timestamp')),
            'last_seen' => array('column' => array('last_seen')),
            'name' => array('column' => array('name')),
            'template_uuid' => array('column' => array('template_uuid')),
            'template_version' => array('column' => array('template_version')),
            'timestamp' => array('column' => array('timestamp')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array('distribution', 'event_id', 'meta-category', 'sharing_group_id'),
    );
}
