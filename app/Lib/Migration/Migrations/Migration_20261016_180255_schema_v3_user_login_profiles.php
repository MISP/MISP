<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: user_login_profiles
 */
class Migration_20261016_180255_schema_v3_user_login_profiles extends TableMigration
{
    public $description = 'Schema modernisation: user_login_profiles';

    const TABLE = 'user_login_profiles';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'created_at' => array('type' => 'datetime', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'status' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'ip' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'user_agent' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'accept_lang' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'geoip' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'ua_platform' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'ua_browser' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'ua_pattern' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'hash' => array('type' => 'string', 'length' => 32, 'null' => false, 'collate' => Collation::ASCII),
        ),
        'indexes' => array(
            'geoip' => array('column' => array('geoip')),
            'hash' => array('column' => array('hash'), 'unique' => true),
            'ip' => array('column' => array('ip')),
            'status' => array('column' => array('status')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
