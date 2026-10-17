<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: tag_collections
 */
class Migration_20261016_180242_schema_v3_tag_collections extends TableMigration
{
    public $description = 'Schema modernisation: tag_collections';

    const TABLE = 'tag_collections';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => Collation::ASCII),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'all_orgs' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'org_id' => array('column' => array('org_id')),
            'user_id' => array('column' => array('user_id')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
