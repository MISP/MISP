<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: galaxy_elements
 */
class Migration_20261016_180331_schema_v3_galaxy_elements extends TableMigration
{
    public $description = 'Schema modernisation: galaxy_elements';

    const TABLE = 'galaxy_elements';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'galaxy_cluster_id' => array('type' => 'biginteger', 'null' => false),
            'key' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
        ),
        'indexes' => array(
            'galaxy_cluster_id' => array('column' => array('galaxy_cluster_id')),
            'key' => array('column' => array('key')),
            'value' => array('column' => array('value'), 'length' => array('value' => 255)),
        ),
        'retired' => array(),
    );
}
