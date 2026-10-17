<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: user_settings
 */
class Migration_20261016_180245_schema_v3_user_settings extends TableMigration
{
    public $description = 'Schema modernisation: user_settings';

    const TABLE = 'user_settings';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'setting' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'value' => array('type' => 'mediumtext', 'null' => false, 'collate' => Collation::BIN),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'timestamp' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'setting' => array('column' => array('setting')),
            'unique_setting' => array('column' => array('user_id', 'setting'), 'unique' => true),
        ),
        'retired' => array('user_id'),
    );
}
