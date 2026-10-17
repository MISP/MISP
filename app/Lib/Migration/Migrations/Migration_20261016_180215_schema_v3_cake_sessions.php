<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: cake_sessions
 */
class Migration_20261016_180215_schema_v3_cake_sessions extends TableMigration
{
    public $description = 'Schema modernisation: cake_sessions';

    const TABLE = 'cake_sessions';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'collate' => Collation::BIN,
                'key' => 'primary',
            ),
            'data' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'expires' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'expires' => array('column' => array('expires')),
        ),
        'retired' => array(),
    );
}
