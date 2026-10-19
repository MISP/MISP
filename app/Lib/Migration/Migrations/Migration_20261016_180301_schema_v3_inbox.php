<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: inbox
 */
class Migration_20261016_180301_schema_v3_inbox extends TableMigration
{
    public $description = 'Schema modernisation: inbox';

    const TABLE = 'inbox';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'title' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'type' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'ip' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'user_agent' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'user_agent_sha256' => array(
                'type' => 'string',
                'length' => 64,
                'null' => false,
                'collate' => Collation::ASCII,
            ),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'timestamp' => array('type' => 'biginteger', 'null' => false),
            'store_as_file' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'data' => array('type' => 'longtext', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'ip' => array('column' => array('ip')),
            'timestamp' => array('column' => array('timestamp')),
            'title' => array('column' => array('title')),
            'type' => array('column' => array('type')),
            'user_agent_sha256' => array('column' => array('user_agent_sha256')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
