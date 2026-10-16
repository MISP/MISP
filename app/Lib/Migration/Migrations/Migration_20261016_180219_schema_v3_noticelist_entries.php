<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: noticelist_entries
 */
class Migration_20261016_180219_schema_v3_noticelist_entries extends TableMigration
{
    public $description = 'Schema modernisation: noticelist_entries';

    const TABLE = 'noticelist_entries';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'noticelist_id' => array('type' => 'biginteger', 'null' => false),
            'data' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'noticelist_id' => array('column' => array('noticelist_id')),
        ),
        'retired' => array(),
    );
}
