<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_reports
 */
class Migration_20261016_180320_schema_v3_event_reports extends TableMigration
{
    public $description = 'Schema modernisation: event_reports';

    const TABLE = 'event_reports';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'content' => array('type' => 'mediumtext', 'null' => true, 'collate' => Collation::CI),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
            'timestamp' => array('type' => 'biginteger', 'null' => false),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'event_id' => array('column' => array('event_id')),
            'name' => array('column' => array('name')),
            'u_uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
