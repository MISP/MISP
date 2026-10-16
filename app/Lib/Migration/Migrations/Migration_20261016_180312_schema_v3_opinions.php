<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: opinions
 */
class Migration_20261016_180312_schema_v3_opinions extends TableMigration
{
    public $description = 'Schema modernisation: opinions';

    const TABLE = 'opinions';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'object_uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'object_sha256' => array('type' => 'string', 'length' => 64, 'null' => true, 'collate' => Collation::ASCII),
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
            'opinion' => array('type' => 'integer', 'unsigned' => true, 'null' => true),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'distribution' => array('column' => array('distribution')),
            'object_sha256' => array('column' => array('object_sha256')),
            'object_type' => array('column' => array('object_type')),
            'object_uuid' => array('column' => array('object_uuid')),
            'opinion' => array('column' => array('opinion')),
            'org_uuid' => array('column' => array('org_uuid')),
            'orgc_uuid' => array('column' => array('orgc_uuid')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
