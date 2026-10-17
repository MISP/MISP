<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: organisations
 */
class Migration_20261016_180311_schema_v3_organisations extends TableMigration
{
    public $description = 'Schema modernisation: organisations';

    const TABLE = 'organisations';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'date_created' => array('type' => 'datetime', 'null' => false),
            'date_modified' => array('type' => 'datetime', 'null' => false),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'type' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'nationality' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'sector' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'created_by' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'contacts' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'local' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'restricted_to_domain' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'landingpage' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'name' => array('column' => array('name'), 'unique' => true),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
