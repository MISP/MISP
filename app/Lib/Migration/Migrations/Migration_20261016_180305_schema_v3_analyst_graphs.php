<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: analyst_graphs
 */
class Migration_20261016_180305_schema_v3_analyst_graphs extends TableMigration
{
    public $description = 'Schema modernisation: analyst_graphs';

    const TABLE = 'analyst_graphs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'object_uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'object_type' => array(
                'type' => 'string',
                'length' => 80,
                'null' => false,
                'collate' => 'ascii_general_ci',
                'charset' => 'ascii',
            ),
            'authors' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'org_uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'orgc_uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
            'distribution' => array('type' => 'tinyinteger', 'null' => false),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
            'locked' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'content' => array('type' => 'longtext', 'null' => false, 'collate' => Collation::CI),
            'content_size' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'node_count' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'revision' => array('type' => 'integer', 'null' => false, 'default' => '1'),
            'forked_from_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => true,
                'collate' => Collation::ASCII,
            ),
        ),
        'indexes' => array(
            'distribution' => array('column' => array('distribution')),
            'forked_from_uuid' => array('column' => array('forked_from_uuid')),
            'object_type' => array('column' => array('object_type')),
            'object_uuid' => array('column' => array('object_uuid')),
            'org_uuid' => array('column' => array('org_uuid')),
            'orgc_uuid' => array('column' => array('orgc_uuid')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
