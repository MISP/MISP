<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: warninglist_entries
 */
class Migration_20261016_180333_schema_v3_warninglist_entries extends TableMigration
{
    public $description = 'Schema modernisation: warninglist_entries';

    const TABLE = 'warninglist_entries';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'warninglist_id' => array('type' => 'biginteger', 'null' => false),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'idx_warn_values' => array('column' => array('value'), 'length' => array('value' => 64)),
            'idx_wle_list_value' => array(
                'column' => array('warninglist_id', 'value'),
                'length' => array('value' => 191),
            ),
            'warninglist_id' => array('column' => array('warninglist_id')),
        ),
        'retired' => array(),
    );
}
