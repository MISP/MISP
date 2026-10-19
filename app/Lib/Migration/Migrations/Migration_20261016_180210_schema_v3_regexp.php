<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: regexp
 */
class Migration_20261016_180210_schema_v3_regexp extends TableMigration
{
    public $description = 'Schema modernisation: regexp';

    const TABLE = 'regexp';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'regexp' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'replacement' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'type' => array(
                'type' => 'string',
                'length' => 100,
                'null' => false,
                'default' => 'ALL',
                'collate' => Collation::BIN,
            ),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
