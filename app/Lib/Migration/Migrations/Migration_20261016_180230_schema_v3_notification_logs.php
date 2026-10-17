<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: notification_logs
 */
class Migration_20261016_180230_schema_v3_notification_logs extends TableMigration
{
    public $description = 'Schema modernisation: notification_logs';

    const TABLE = 'notification_logs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'type' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id')),
            'type' => array('column' => array('type')),
        ),
        'retired' => array(),
    );
}
