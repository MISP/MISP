<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: galaxy_cluster_relation_tags
 */
class Migration_20261016_180322_schema_v3_galaxy_cluster_relation_tags extends TableMigration
{
    public $description = 'Schema modernisation: galaxy_cluster_relation_tags';

    const TABLE = 'galaxy_cluster_relation_tags';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'galaxy_cluster_relation_id' => array('type' => 'biginteger', 'null' => false),
            'tag_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'galaxy_cluster_relation_id' => array('column' => array('galaxy_cluster_relation_id')),
            'tag_id' => array('column' => array('tag_id')),
        ),
        'retired' => array(),
    );
}
