<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: access_logs
 */
class Migration_20261016_180327_schema_v3_access_logs extends TableMigration
{
    public $description = 'Schema modernisation: access_logs';

    const TABLE = 'access_logs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'created' => array('type' => 'datetime', 'length' => 4, 'null' => false),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'authkey_id' => array('type' => 'biginteger', 'null' => true),
            'ip' => array('type' => 'varbinary', 'length' => 16, 'null' => true),
            'request_method' => array('type' => 'tinyinteger', 'null' => false),
            'user_agent' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'request_id' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'controller' => array('type' => 'string', 'length' => 20, 'null' => false, 'collate' => Collation::CI),
            'action' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'url' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'request' => array('type' => 'binary', 'null' => true),
            'response_code' => array('type' => 'smallinteger', 'null' => false),
            'memory_usage' => array('type' => 'integer', 'null' => false),
            'duration' => array('type' => 'integer', 'null' => false),
            'query_count' => array('type' => 'integer', 'null' => false),
            'query_log' => array('type' => 'binary', 'null' => true),
        ),
        'indexes' => array(
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
