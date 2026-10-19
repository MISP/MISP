<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: galaxy_cluster_blocklists
 */
class Migration_20261016_180228_schema_v3_galaxy_cluster_blocklists extends TableMigration
{
    public $description = 'Schema modernisation: galaxy_cluster_blocklists';

    const TABLE = 'galaxy_cluster_blocklists';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'cluster_uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'created' => array('type' => 'datetime', 'null' => false),
            'cluster_info' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'cluster_orgc' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
        ),
        'indexes' => array(
            'cluster_orgc' => array('column' => array('cluster_orgc')),
            'cluster_uuid' => array('column' => array('cluster_uuid')),
        ),
        'retired' => array(),
    );
}
