<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: dashboards
 */
class Migration_20261016_180303_schema_v3_dashboards extends TableMigration
{
    public $description = 'Schema modernisation: dashboards';

    const TABLE = 'dashboards';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'selectable' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'user_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'restrict_to_org_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'restrict_to_role_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'restrict_to_permission_flag' => array(
                'type' => 'string',
                'length' => 191,
                'null' => false,
                'default' => '',
                'collate' => Collation::CI,
            ),
            'value' => array('type' => 'mediumtext', 'null' => true, 'collate' => Collation::CI),
            'timestamp' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
            'restrict_to_org_id' => array('column' => array('restrict_to_org_id')),
            'restrict_to_permission_flag' => array('column' => array('restrict_to_permission_flag')),
            'user_id' => array('column' => array('user_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
