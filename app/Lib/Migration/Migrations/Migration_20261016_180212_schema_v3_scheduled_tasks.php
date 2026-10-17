<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: scheduled_tasks
 */
class Migration_20261016_180212_schema_v3_scheduled_tasks extends TableMigration
{
    public $description = 'Schema modernisation: scheduled_tasks';

    const TABLE = 'scheduled_tasks';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'type' => array('type' => 'string', 'length' => 100, 'null' => false, 'collate' => Collation::CI),
            'timer' => array('type' => 'integer', 'null' => false),
            'last_job_id' => array('type' => 'biginteger', 'null' => true),
            'description' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'next_execution_time' => array('type' => 'biginteger', 'null' => false),
            'message' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'action' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::CI),
            'params' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'enabled' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'last_run_at' => array('type' => 'biginteger', 'null' => true),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
