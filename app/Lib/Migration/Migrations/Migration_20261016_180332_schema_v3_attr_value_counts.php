<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: attr_value_counts
 */
class Migration_20261016_180332_schema_v3_attr_value_counts extends TableMigration
{
    public $description = 'Schema modernisation: attr_value_counts';

    const TABLE = 'attr_value_counts';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'value_id' => array('type' => 'biginteger', 'null' => false),
            'cnt_v1' => array('type' => 'biginteger', 'unsigned' => true, 'null' => false, 'default' => '0'),
            'cnt_v2' => array('type' => 'biginteger', 'unsigned' => true, 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'value_id' => array('column' => array('value_id'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
