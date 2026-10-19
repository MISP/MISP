<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: warninglist_types
 */
class Migration_20261016_180246_schema_v3_warninglist_types extends TableMigration
{
    public $description = 'Schema modernisation: warninglist_types';

    const TABLE = 'warninglist_types';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'type' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'warninglist_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
