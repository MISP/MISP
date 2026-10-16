<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: workflow_blueprints
 */
class Migration_20261016_180247_schema_v3_workflow_blueprints extends TableMigration
{
    public $description = 'Schema modernisation: workflow_blueprints';

    const TABLE = 'workflow_blueprints';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'data' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
            'timestamp' => array('column' => array('timestamp')),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
