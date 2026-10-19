<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: galaxy_cluster_relations
 */
class Migration_20261016_180328_schema_v3_galaxy_cluster_relations extends TableMigration
{
    public $description = 'Schema modernisation: galaxy_cluster_relations';

    const TABLE = 'galaxy_cluster_relations';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'galaxy_cluster_id' => array('type' => 'biginteger', 'null' => false),
            'referenced_galaxy_cluster_id' => array('type' => 'biginteger', 'null' => false),
            'referenced_galaxy_cluster_uuid' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'collate' => Collation::ASCII,
            ),
            'referenced_galaxy_cluster_type' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'galaxy_cluster_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => false,
                'collate' => Collation::ASCII,
            ),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'default' => array('column' => array('default')),
            'galaxy_cluster_id' => array('column' => array('galaxy_cluster_id')),
            'galaxy_cluster_uuid' => array('column' => array('galaxy_cluster_uuid')),
            'referenced_galaxy_cluster_id' => array('column' => array('referenced_galaxy_cluster_id')),
            'referenced_galaxy_cluster_type' => array(
                'column' => array('referenced_galaxy_cluster_type'),
                'length' => array('referenced_galaxy_cluster_type' => 255),
            ),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
        ),
        'retired' => array(),
    );
}
