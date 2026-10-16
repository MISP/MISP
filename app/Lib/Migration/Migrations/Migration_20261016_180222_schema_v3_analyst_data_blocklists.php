<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: analyst_data_blocklists
 */
class Migration_20261016_180222_schema_v3_analyst_data_blocklists extends TableMigration
{
    public $description = 'Schema modernisation: analyst_data_blocklists';

    const TABLE = 'analyst_data_blocklists';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'analyst_data_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => false,
                'collate' => Collation::ASCII,
            ),
            'created' => array('type' => 'datetime', 'null' => false),
            'analyst_data_info' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'analyst_data_orgc' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'collate' => Collation::BIN,
            ),
        ),
        'indexes' => array(
            'analyst_data_orgc' => array('column' => array('analyst_data_orgc')),
            'analyst_data_uuid' => array('column' => array('analyst_data_uuid')),
        ),
        'retired' => array(),
    );
}
