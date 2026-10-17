<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sighting_blocklists
 */
class Migration_20261016_180232_schema_v3_sighting_blocklists extends TableMigration
{
    public $description = 'Schema modernisation: sighting_blocklists';

    const TABLE = 'sighting_blocklists';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'created' => array('type' => 'datetime', 'null' => false),
            'org_name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'org_name' => array('column' => array('org_name')),
            'org_uuid' => array('column' => array('org_uuid')),
        ),
        'retired' => array(),
    );
}
