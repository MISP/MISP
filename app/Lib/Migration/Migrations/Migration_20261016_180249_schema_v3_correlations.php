<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: correlations
 */
class Migration_20261016_180249_schema_v3_correlations extends TableMigration
{
    public $description = 'Schema modernisation: correlations';

    const TABLE = 'correlations';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            '1_event_id' => array('type' => 'biginteger', 'null' => false),
            '1_attribute_id' => array('type' => 'biginteger', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'attribute_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'distribution' => array('type' => 'tinyinteger', 'null' => false),
            'a_distribution' => array('type' => 'tinyinteger', 'null' => false),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false),
            'a_sharing_group_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            '1_attribute_id' => array('column' => array('1_attribute_id')),
            '1_event_id' => array('column' => array('1_event_id')),
            'attribute_id' => array('column' => array('attribute_id')),
            'event_id' => array('column' => array('event_id')),
        ),
        'retired' => array(),
    );
}
