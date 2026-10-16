<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: value_enrichment_runs
 */
class Migration_20261016_180235_schema_v3_value_enrichment_runs extends TableMigration
{
    public $description = 'Schema modernisation: value_enrichment_runs';

    const TABLE = 'value_enrichment_runs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'value_hash' => array('type' => 'string', 'length' => 64, 'null' => false, 'collate' => Collation::ASCII),
            'value' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'module' => array('type' => 'string', 'length' => 100, 'null' => false, 'collate' => Collation::CI),
            'type' => array('type' => 'string', 'length' => 100, 'null' => false, 'collate' => Collation::CI),
            'state' => array('type' => 'string', 'length' => 32, 'null' => false, 'collate' => Collation::CI),
            'user_id' => array('type' => 'biginteger', 'null' => true),
            'last_run' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'took' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'total' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'shown' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'capped' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'message' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'result' => array('type' => 'binary', 'null' => true),
        ),
        'indexes' => array(
            'last_run' => array('column' => array('last_run')),
            'run' => array('column' => array('org_id', 'value_hash', 'module', 'type'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
