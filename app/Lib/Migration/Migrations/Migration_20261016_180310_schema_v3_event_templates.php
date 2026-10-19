<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_templates
 */
class Migration_20261016_180310_schema_v3_event_templates extends TableMigration
{
    public $description = 'Schema modernisation: event_templates';

    const TABLE = 'event_templates';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'creator_user_id' => array('type' => 'biginteger', 'null' => false),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'active' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
            'misp_default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'exposed' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'version' => array('type' => 'integer', 'unsigned' => true, 'null' => false, 'default' => '1'),
            'definition' => array('type' => 'mediumtext', 'null' => false, 'collate' => Collation::CI),
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
        ),
        'indexes' => array(
            'active' => array('column' => array('active')),
            'exposed' => array('column' => array('exposed')),
            'name' => array('column' => array('name')),
            'org_id' => array('column' => array('org_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
