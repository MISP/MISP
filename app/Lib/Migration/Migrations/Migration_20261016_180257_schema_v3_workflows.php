<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: workflows
 */
class Migration_20261016_180257_schema_v3_workflows extends TableMigration
{
    public $description = 'Schema modernisation: workflows';

    const TABLE = 'workflows';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'counter' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'trigger_id' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::BIN),
            'debug_enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'data' => array('type' => 'longtext', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
            'timestamp' => array('column' => array('timestamp')),
            'trigger_id' => array('column' => array('trigger_id')),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
