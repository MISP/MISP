<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_locks
 */
class Migration_20261016_180238_schema_v3_event_locks extends TableMigration
{
    public $description = 'Schema modernisation: event_locks';

    const TABLE = 'event_locks';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'event_id' => array('column' => array('event_id')),
            'timestamp' => array('column' => array('timestamp')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
