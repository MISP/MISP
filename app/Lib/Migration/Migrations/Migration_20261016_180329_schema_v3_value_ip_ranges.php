<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: value_ip_ranges
 */
class Migration_20261016_180329_schema_v3_value_ip_ranges extends TableMigration
{
    public $description = 'Schema modernisation: value_ip_ranges';

    const TABLE = 'value_ip_ranges';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'value_id' => array('type' => 'biginteger', 'null' => false),
            'ip_start' => array('type' => 'varbinary', 'length' => 16, 'null' => false),
            'ip_end' => array('type' => 'varbinary', 'length' => 16, 'null' => false),
            'prefix' => array('type' => 'tinyinteger', 'unsigned' => true, 'null' => false),
        ),
        'indexes' => array(
            'start_end' => array('column' => array('ip_start', 'ip_end', 'value_id')),
            'value_id' => array('column' => array('value_id'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
