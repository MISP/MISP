<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: bookmarks
 */
class Migration_20261016_180236_schema_v3_bookmarks extends TableMigration
{
    public $description = 'Schema modernisation: bookmarks';

    const TABLE = 'bookmarks';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::BIN),
            'url' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'exposed_to_org' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
            'org_id' => array('column' => array('org_id')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
