<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: object_templates
 */
class Migration_20261016_180318_schema_v3_object_templates extends TableMigration
{
    public $description = 'Schema modernisation: object_templates';

    const TABLE = 'object_templates';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'meta-category' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'version' => array('type' => 'integer', 'null' => false),
            'requirements' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'fixed' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'active' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'meta-category' => array('column' => array('meta-category')),
            'name' => array('column' => array('name')),
            'org_id' => array('column' => array('org_id')),
            'user_id' => array('column' => array('user_id')),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
