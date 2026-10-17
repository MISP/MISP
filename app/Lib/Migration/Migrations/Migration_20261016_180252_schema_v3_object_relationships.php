<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: object_relationships
 */
class Migration_20261016_180252_schema_v3_object_relationships extends TableMigration
{
    public $description = 'Schema modernisation: object_relationships';

    const TABLE = 'object_relationships';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'version' => array('type' => 'integer', 'null' => false),
            'name' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'format' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'highlighted' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
        ),
        'retired' => array(),
    );
}
