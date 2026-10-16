<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: correlation_exclusions
 */
class Migration_20261016_180216_schema_v3_correlation_exclusions extends TableMigration
{
    public $description = 'Schema modernisation: correlation_exclusions';

    const TABLE = 'correlation_exclusions';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'from_json' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'value' => array('column' => array('value'), 'unique' => true, 'length' => array('value' => 191)),
        ),
        'retired' => array(),
    );
}
