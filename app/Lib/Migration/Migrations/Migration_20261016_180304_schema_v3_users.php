<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: users
 */
class Migration_20261016_180304_schema_v3_users extends TableMigration
{
    public $description = 'Schema modernisation: users';

    const TABLE = 'users';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'password' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'server_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'email' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'autoalert' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'authkey' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'invited_by' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'gpgkey' => array('type' => 'longtext', 'null' => true, 'collate' => Collation::BIN),
            'certif_public' => array('type' => 'longtext', 'null' => true, 'collate' => Collation::BIN),
            'nids_sid' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'termsaccepted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'newsread' => array('type' => 'biginteger', 'null' => true, 'default' => '0'),
            'role_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'change_pw' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'contactalert' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'disabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'expiration' => array('type' => 'datetime', 'null' => true),
            'current_login' => array('type' => 'biginteger', 'null' => true, 'default' => '0'),
            'last_login' => array('type' => 'biginteger', 'null' => true, 'default' => '0'),
            'force_logout' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'date_created' => array('type' => 'biginteger', 'null' => true),
            'date_modified' => array('type' => 'biginteger', 'null' => true),
            'sub' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::BIN),
            'external_auth_required' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'external_auth_key' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'last_api_access' => array('type' => 'biginteger', 'null' => true, 'default' => '0'),
            'notification_daily' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'notification_weekly' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'notification_monthly' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'totp' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::BIN),
            'hotp_counter' => array('type' => 'integer', 'null' => true),
            'last_pw_change' => array('type' => 'biginteger', 'null' => true),
        ),
        'indexes' => array(
            'email' => array('column' => array('email'), 'unique' => true),
            'org_id' => array('column' => array('org_id')),
            'server_id' => array('column' => array('server_id')),
            'sub' => array('column' => array('sub'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
