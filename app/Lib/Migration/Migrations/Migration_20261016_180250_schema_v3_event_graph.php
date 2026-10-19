<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_graph
 */
class Migration_20261016_180250_schema_v3_event_graph extends TableMigration
{
    public $description = 'Schema modernisation: event_graph';

    const TABLE = 'event_graph';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'network_name' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'network_json' => array('type' => 'mediumtext', 'null' => false, 'collate' => Collation::CI),
            'preview_img' => array('type' => 'mediumtext', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'event_id' => array('column' => array('event_id')),
            'org_id' => array('column' => array('org_id')),
            'timestamp' => array('column' => array('timestamp')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
