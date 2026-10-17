<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: analyst_profiles
 */
class Migration_20261016_180306_schema_v3_analyst_profiles extends TableMigration
{
    public $description = 'Schema modernisation: analyst_profiles';

    const TABLE = 'analyst_profiles';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'user_id' => array('type' => 'biginteger', 'null' => true),
            'org_id' => array('type' => 'biginteger', 'null' => true),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'shared' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
            'version' => array('type' => 'integer', 'null' => false, 'default' => '1'),
            'revision' => array('type' => 'integer', 'null' => false, 'default' => '1'),
            'parameters' => array('type' => 'longtext', 'null' => true, 'collate' => Collation::CI),
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
        ),
        'indexes' => array(
            'default' => array('column' => array('default')),
            'enabled' => array('column' => array('enabled')),
            'name' => array('column' => array('name')),
            'org_id' => array('column' => array('org_id')),
            'shared' => array('column' => array('shared')),
            'user_id' => array('column' => array('user_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
