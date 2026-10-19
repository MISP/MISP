<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: analyst_profile_selections
 */
class Migration_20261016_180223_schema_v3_analyst_profile_selections extends TableMigration
{
    public $description = 'Schema modernisation: analyst_profile_selections';

    const TABLE = 'analyst_profile_selections';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'modified' => array('type' => 'datetime', 'null' => false),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id'), 'unique' => true),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
