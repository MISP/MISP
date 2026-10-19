<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: cerebrates
 */
class Migration_20261016_180248_schema_v3_cerebrates extends TableMigration
{
    public $description = 'Schema modernisation: cerebrates';

    const TABLE = 'cerebrates';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'url' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'authkey' => array('type' => 'varbinary', 'length' => 255, 'null' => false),
            'open' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'pull_orgs' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'pull_sharing_groups' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'self_signed' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'cert_file' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'client_cert_file' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'collate' => Collation::CI,
            ),
            'internal' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'skip_proxy' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id')),
            'url' => array('column' => array('url')),
        ),
        'retired' => array(),
    );
}
