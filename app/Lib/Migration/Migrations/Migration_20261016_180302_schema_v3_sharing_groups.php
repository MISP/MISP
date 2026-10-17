<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sharing_groups
 */
class Migration_20261016_180302_schema_v3_sharing_groups extends TableMigration
{
    public $description = 'Schema modernisation: sharing_groups';

    const TABLE = 'sharing_groups';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'releasability' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'organisation_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => false,
                'collate' => Collation::ASCII,
            ),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'sync_user_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'active' => array('type' => 'boolean', 'null' => false),
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
            'local' => array('type' => 'boolean', 'null' => false),
            'roaming' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'name' => array('column' => array('name'), 'unique' => true),
            'org_id' => array('column' => array('org_id')),
            'organisation_uuid' => array('column' => array('organisation_uuid')),
            'sync_user_id' => array('column' => array('sync_user_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
