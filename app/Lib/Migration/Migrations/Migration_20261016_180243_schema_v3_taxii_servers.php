<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: taxii_servers
 */
class Migration_20261016_180243_schema_v3_taxii_servers extends TableMigration
{
    public $description = 'Schema modernisation: taxii_servers';

    const TABLE = 'taxii_servers';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'owner' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'discovery_url' => array('type' => 'string', 'length' => 512, 'null' => true, 'collate' => Collation::CI),
            'api_root' => array('type' => 'string', 'length' => 1024, 'null' => true, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'filters' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'api_key' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'auth_type' => array(
                'type' => 'string',
                'length' => 191,
                'null' => true,
                'default' => 'basic',
                'collate' => Collation::CI,
            ),
            'collection' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::CI),
            'skip_proxy' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
        ),
        'indexes' => array(
            'baseurl' => array('column' => array('discovery_url')),
            'name' => array('column' => array('name')),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
