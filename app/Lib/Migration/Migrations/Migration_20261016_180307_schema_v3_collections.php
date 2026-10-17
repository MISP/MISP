<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: collections
 */
class Migration_20261016_180307_schema_v3_collections extends TableMigration
{
    public $description = 'Schema modernisation: collections';

    const TABLE = 'collections';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'orgc_id' => array('type' => 'biginteger', 'null' => false),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
            'distribution' => array('type' => 'tinyinteger', 'null' => false),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'type' => array(
                'type' => 'string',
                'length' => 80,
                'null' => false,
                'collate' => 'ascii_general_ci',
                'charset' => 'ascii',
            ),
            'description' => array('type' => 'mediumtext', 'null' => true, 'collate' => Collation::CI),
            'locked' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'distribution' => array('column' => array('distribution')),
            'name' => array('column' => array('name')),
            'org_id' => array('column' => array('org_id')),
            'orgc_id' => array('column' => array('orgc_id')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
            'type' => array('column' => array('type')),
            'user_id' => array('column' => array('user_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
