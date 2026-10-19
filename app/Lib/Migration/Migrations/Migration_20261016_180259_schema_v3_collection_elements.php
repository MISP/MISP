<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: collection_elements
 */
class Migration_20261016_180259_schema_v3_collection_elements extends TableMigration
{
    public $description = 'Schema modernisation: collection_elements';

    const TABLE = 'collection_elements';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'element_uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'element_sha256' => array(
                'type' => 'string',
                'length' => 64,
                'null' => true,
                'collate' => Collation::ASCII,
            ),
            'element_type' => array(
                'type' => 'string',
                'length' => 80,
                'null' => false,
                'collate' => 'ascii_general_ci',
                'charset' => 'ascii',
            ),
            'collection_id' => array('type' => 'biginteger', 'null' => false),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'collection_id' => array('column' => array('collection_id')),
            'element_type' => array('column' => array('element_type')),
            'unique_element' => array('column' => array('element_uuid', 'collection_id'), 'unique' => true),
            'unique_element_sha256' => array('column' => array('element_sha256', 'collection_id'), 'unique' => true),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array('element_uuid'),
    );
}
