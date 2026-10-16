<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: object_references
 */
class Migration_20261016_180335_schema_v3_object_references extends TableMigration
{
    public $description = 'Schema modernisation: object_references';

    const TABLE = 'object_references';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'object_id' => array('type' => 'biginteger', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'source_uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'referenced_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => true,
                'collate' => Collation::ASCII,
            ),
            'referenced_id' => array('type' => 'biginteger', 'null' => false),
            'referenced_type' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'relationship_type' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'collate' => Collation::CI,
            ),
            'comment' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'event_id' => array('column' => array('event_id')),
            'object_id' => array('column' => array('object_id')),
            'referenced_id' => array('column' => array('referenced_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
