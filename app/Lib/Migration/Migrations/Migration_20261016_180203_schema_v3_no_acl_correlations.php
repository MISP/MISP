<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: no_acl_correlations
 */
class Migration_20261016_180203_schema_v3_no_acl_correlations extends TableMigration
{
    public $description = 'Schema modernisation: no_acl_correlations';

    const TABLE = 'no_acl_correlations';

    const RECREATE = true;

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'attribute_id' => array('type' => 'biginteger', 'null' => false),
            '1_attribute_id' => array('type' => 'biginteger', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            '1_event_id' => array('type' => 'biginteger', 'null' => false),
            'value_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            '1_event_id' => array('column' => array('1_event_id')),
            'idx_nac_1attr_1evt' => array('column' => array('1_attribute_id', '1_event_id')),
            'idx_nac_attr_evt' => array('column' => array('attribute_id', 'event_id')),
            'idx_nac_evt_1evt' => array('column' => array('event_id', '1_event_id')),
            'idx_nac_val_1attr' => array('column' => array('value_id', '1_attribute_id')),
            'idx_nac_val_attr' => array('column' => array('value_id', 'attribute_id')),
            'unique_correlation' => array(
                'column' => array('attribute_id', '1_attribute_id', 'value_id'),
                'unique' => true,
            ),
        ),
        'retired' => array('1_attribute_id', 'attribute_id', 'event_id', 'value_id'),
    );
}
