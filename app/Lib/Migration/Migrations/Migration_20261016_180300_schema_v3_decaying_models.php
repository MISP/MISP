<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: decaying_models
 */
class Migration_20261016_180300_schema_v3_decaying_models extends TableMigration
{
    public $description = 'Schema modernisation: decaying_models';

    const TABLE = 'decaying_models';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'parameters' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'attribute_types' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'org_id' => array('type' => 'biginteger', 'null' => true),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'all_orgs' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
            'ref' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'formula' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'version' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'all_orgs' => array('column' => array('all_orgs')),
            'enabled' => array('column' => array('enabled')),
            'name' => array('column' => array('name')),
            'org_id' => array('column' => array('org_id')),
            'uuid' => array('column' => array('uuid')),
            'version' => array('column' => array('version')),
        ),
        'retired' => array(),
    );
}
