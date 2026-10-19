<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sharing_group_servers
 */
class Migration_20261016_180231_schema_v3_sharing_group_servers extends TableMigration
{
    public $description = 'Schema modernisation: sharing_group_servers';

    const TABLE = 'sharing_group_servers';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false),
            'server_id' => array('type' => 'biginteger', 'null' => false),
            'all_orgs' => array('type' => 'boolean', 'null' => false),
        ),
        'indexes' => array(
            'server_id' => array('column' => array('server_id')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
        ),
        'retired' => array(),
    );
}
