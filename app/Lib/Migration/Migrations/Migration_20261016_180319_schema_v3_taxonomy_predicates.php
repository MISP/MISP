<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: taxonomy_predicates
 */
class Migration_20261016_180319_schema_v3_taxonomy_predicates extends TableMigration
{
    public $description = 'Schema modernisation: taxonomy_predicates';

    const TABLE = 'taxonomy_predicates';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'taxonomy_id' => array('type' => 'biginteger', 'null' => false),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'expanded' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'colour' => array('type' => 'string', 'length' => 7, 'null' => true, 'collate' => Collation::BIN),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'exclusive' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'numerical_value' => array('type' => 'integer', 'null' => true),
        ),
        'indexes' => array(
            'numerical_value' => array('column' => array('numerical_value')),
            'taxonomy_id' => array('column' => array('taxonomy_id')),
        ),
        'retired' => array(),
    );
}
