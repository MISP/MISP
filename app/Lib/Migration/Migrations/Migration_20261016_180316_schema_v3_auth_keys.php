<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: auth_keys
 */
class Migration_20261016_180316_schema_v3_auth_keys extends TableMigration
{
    public $description = 'Schema modernisation: auth_keys';

    const TABLE = 'auth_keys';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'authkey' => array('type' => 'string', 'length' => 72, 'null' => false, 'collate' => Collation::ASCII),
            'authkey_start' => array('type' => 'string', 'length' => 4, 'null' => false, 'collate' => Collation::ASCII),
            'authkey_end' => array('type' => 'string', 'length' => 4, 'null' => false, 'collate' => Collation::ASCII),
            'created' => array('type' => 'biginteger', 'null' => false),
            'expiration' => array('type' => 'biginteger', 'null' => false),
            'read_only' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'allowed_ips' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'unique_ips' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'authkey_end' => array('column' => array('authkey_end')),
            'authkey_start' => array('column' => array('authkey_start')),
            'created' => array('column' => array('created')),
            'expiration' => array('column' => array('expiration')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
