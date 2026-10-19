<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: over_correlating_values
 */
class Migration_20261016_180204_schema_v3_over_correlating_values extends TableMigration
{
    public $description = 'Schema modernisation: over_correlating_values';

    const TABLE = 'over_correlating_values';

    const RECREATE = true;

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'value_id' => array('type' => 'biginteger', 'null' => true),
            'occurrence' => array('type' => 'integer', 'unsigned' => true, 'null' => true),
        ),
        'indexes' => array(
            'occurrence' => array('column' => array('occurrence')),
            'value_id' => array('column' => array('value_id'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
