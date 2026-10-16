<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: galaxies
 */
class Migration_20261016_180313_schema_v3_galaxies extends TableMigration
{
    public $description = 'Schema modernisation: galaxies';

    const TABLE = 'galaxies';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'type' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'description' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'version' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'icon' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'namespace' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => 'misp',
                'collate' => Collation::CI,
            ),
            'category' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::BIN),
            'sub_category' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::BIN),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
            'local_only' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'kill_chain_order' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'orgc_id' => array('type' => 'biginteger', 'null' => false),
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
            'distribution' => array('type' => 'tinyinteger', 'null' => false),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
            'namespace' => array('column' => array('namespace')),
            'type' => array('column' => array('type')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
