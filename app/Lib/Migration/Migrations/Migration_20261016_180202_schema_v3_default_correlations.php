<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: default_correlations
 */
class Migration_20261016_180202_schema_v3_default_correlations extends TableMigration
{
    public $description = 'Schema modernisation: default_correlations';

    const TABLE = 'default_correlations';

    const RECREATE = true;

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'attribute_id' => array('type' => 'biginteger', 'null' => false),
            'object_id' => array('type' => 'biginteger', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'distribution' => array('type' => 'tinyinteger', 'null' => false),
            'object_distribution' => array('type' => 'tinyinteger', 'null' => false),
            'event_distribution' => array('type' => 'tinyinteger', 'null' => false),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'object_sharing_group_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'event_sharing_group_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            '1_attribute_id' => array('type' => 'biginteger', 'null' => false),
            '1_object_id' => array('type' => 'biginteger', 'null' => false),
            '1_event_id' => array('type' => 'biginteger', 'null' => false),
            '1_org_id' => array('type' => 'biginteger', 'null' => false),
            '1_distribution' => array('type' => 'tinyinteger', 'null' => false),
            '1_object_distribution' => array('type' => 'tinyinteger', 'null' => false),
            '1_event_distribution' => array('type' => 'tinyinteger', 'null' => false),
            '1_sharing_group_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            '1_object_sharing_group_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            '1_event_sharing_group_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'value_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            '1_attribute_id' => array('column' => array('1_attribute_id')),
            '1_event_id' => array('column' => array('1_event_id')),
            'idx_corr_acl_dst' => array(
                'column' => array(
                    '1_object_id',
                    '1_org_id',
                    '1_distribution',
                    '1_sharing_group_id',
                    '1_event_distribution',
                    '1_event_sharing_group_id',
                ),
            ),
            'idx_corr_acl_dst_obj' => array(
                'column' => array(
                    '1_object_id',
                    '1_org_id',
                    '1_distribution',
                    '1_sharing_group_id',
                    '1_object_distribution',
                    '1_object_sharing_group_id',
                    '1_event_distribution',
                    '1_event_sharing_group_id',
                ),
            ),
            'idx_corr_acl_src' => array(
                'column' => array(
                    'object_id',
                    'org_id',
                    'distribution',
                    'sharing_group_id',
                    'event_distribution',
                    'event_sharing_group_id',
                ),
            ),
            'idx_corr_acl_src_obj' => array(
                'column' => array(
                    'object_id',
                    'org_id',
                    'distribution',
                    'sharing_group_id',
                    'object_distribution',
                    'object_sharing_group_id',
                    'event_distribution',
                    'event_sharing_group_id',
                ),
            ),
            'idx_corr_evt_1evt' => array('column' => array('event_id', '1_event_id')),
            'unique_correlation' => array(
                'column' => array('attribute_id', '1_attribute_id', 'value_id'),
                'unique' => true,
            ),
            'value_id' => array('column' => array('value_id')),
        ),
        'retired' => array('1_object_id', 'attribute_id', 'event_id', 'object_id'),
    );
}
