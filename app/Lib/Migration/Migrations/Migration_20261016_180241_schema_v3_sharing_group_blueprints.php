<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sharing_group_blueprints
 */
class Migration_20261016_180241_schema_v3_sharing_group_blueprints extends TableMigration
{
    public $description = 'Schema modernisation: sharing_group_blueprints';

    const TABLE = 'sharing_group_blueprints';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
            'rules' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
            'org_id' => array('column' => array('org_id')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
