<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: system_settings
 */
class Migration_20261016_180221_schema_v3_system_settings extends TableMigration
{
    public $description = 'Schema modernisation: system_settings';

    const TABLE = 'system_settings';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'setting' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'value' => array('type' => 'binary', 'null' => false),
        ),
        'indexes' => array(
            'setting' => array('column' => array('setting'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
