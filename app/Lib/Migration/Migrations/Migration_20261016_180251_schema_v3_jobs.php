<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: jobs
 */
class Migration_20261016_180251_schema_v3_jobs extends TableMigration
{
    public $description = 'Schema modernisation: jobs';

    const TABLE = 'jobs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'worker' => array('type' => 'string', 'length' => 32, 'null' => false, 'collate' => Collation::BIN),
            'job_type' => array('type' => 'string', 'length' => 32, 'null' => false, 'collate' => Collation::BIN),
            'job_input' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'status' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'retries' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'message' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'progress' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'org_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'process_id' => array('type' => 'string', 'length' => 36, 'null' => true, 'collate' => Collation::BIN),
            'date_created' => array('type' => 'datetime', 'null' => false),
            'date_modified' => array('type' => 'datetime', 'null' => false),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
