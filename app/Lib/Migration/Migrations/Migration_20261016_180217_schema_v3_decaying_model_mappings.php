<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: decaying_model_mappings
 */
class Migration_20261016_180217_schema_v3_decaying_model_mappings extends TableMigration
{
    public $description = 'Schema modernisation: decaying_model_mappings';

    const TABLE = 'decaying_model_mappings';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'attribute_type' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'collate' => Collation::BIN,
            ),
            'model_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'model_id' => array('column' => array('model_id')),
        ),
        'retired' => array(),
    );
}
