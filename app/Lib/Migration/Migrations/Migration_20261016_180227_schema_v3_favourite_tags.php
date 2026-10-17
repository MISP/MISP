<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: favourite_tags
 */
class Migration_20261016_180227_schema_v3_favourite_tags extends TableMigration
{
    public $description = 'Schema modernisation: favourite_tags';

    const TABLE = 'favourite_tags';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'tag_id' => array('type' => 'biginteger', 'null' => false),
            'user_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'tag_id' => array('column' => array('tag_id')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );
}
