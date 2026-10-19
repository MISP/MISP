<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sightingdb_orgs
 */
class Migration_20261016_180233_schema_v3_sightingdb_orgs extends TableMigration
{
    public $description = 'Schema modernisation: sightingdb_orgs';

    const TABLE = 'sightingdb_orgs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'sightingdb_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id')),
            'sightingdb_id' => array('column' => array('sightingdb_id')),
        ),
        'retired' => array(),
    );
}
