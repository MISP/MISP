<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sharing_group_orgs
 */
class Migration_20261016_180253_schema_v3_sharing_group_orgs extends TableMigration
{
    public $description = 'Schema modernisation: sharing_group_orgs';

    const TABLE = 'sharing_group_orgs';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'extend' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
        ),
        'retired' => array(),
    );
}
