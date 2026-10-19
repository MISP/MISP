<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: object_template_elements
 */
class Migration_20261016_180321_schema_v3_object_template_elements extends TableMigration
{
    public $description = 'Schema modernisation: object_template_elements';

    const TABLE = 'object_template_elements';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'object_template_id' => array('type' => 'biginteger', 'null' => false),
            'object_relation' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'collate' => Collation::BIN,
            ),
            'type' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::BIN),
            'ui-priority' => array('type' => 'integer', 'null' => false),
            'categories' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'sane_default' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'values_list' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'disable_correlation' => array('type' => 'boolean', 'null' => true),
            'multiple' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'object_relation' => array('column' => array('object_relation')),
            'object_template_id' => array('column' => array('object_template_id')),
            'type' => array('column' => array('type')),
        ),
        'retired' => array(),
    );
}
