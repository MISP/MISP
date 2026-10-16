<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: rest_client_histories
 */
class Migration_20261016_180239_schema_v3_rest_client_histories extends TableMigration
{
    public $description = 'Schema modernisation: rest_client_histories';

    const TABLE = 'rest_client_histories';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'headers' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'body' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'url' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'http_method' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'use_full_path' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'show_result' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'skip_ssl' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'outcome' => array('type' => 'integer', 'null' => false),
            'bookmark' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'bookmark_name' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => '',
                'collate' => Collation::CI,
            ),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id')),
            'timestamp' => array('column' => array('timestamp')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
