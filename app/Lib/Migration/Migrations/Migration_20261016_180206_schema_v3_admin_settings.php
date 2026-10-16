<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: admin_settings
 */
class Migration_20261016_180206_schema_v3_admin_settings extends TableMigration
{
    public $description = 'Schema modernisation: admin_settings';

    const TABLE = 'admin_settings';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'setting' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
        ),
        'indexes' => array(
            'setting' => array('column' => array('setting'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
