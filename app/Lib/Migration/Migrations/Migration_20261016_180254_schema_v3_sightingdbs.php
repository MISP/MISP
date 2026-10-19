<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sightingdbs
 */
class Migration_20261016_180254_schema_v3_sightingdbs extends TableMigration
{
    public $description = 'Schema modernisation: sightingdbs';

    const TABLE = 'sightingdbs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'owner' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => '',
                'collate' => Collation::CI,
            ),
            'host' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => 'http://localhost',
                'collate' => Collation::CI,
            ),
            'port' => array('type' => 'integer', 'null' => true, 'default' => '9999'),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'skip_proxy' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'ssl_skip_verification' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'namespace' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => '',
                'collate' => Collation::CI,
            ),
        ),
        'indexes' => array(
            'host' => array('column' => array('host')),
            'name' => array('column' => array('name')),
            'owner' => array('column' => array('owner')),
            'port' => array('column' => array('port')),
        ),
        'retired' => array(),
    );
}
