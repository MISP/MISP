<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: tag_collection_tags
 */
class Migration_20261016_180234_schema_v3_tag_collection_tags extends TableMigration
{
    public $description = 'Schema modernisation: tag_collection_tags';

    const TABLE = 'tag_collection_tags';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'tag_collection_id' => array('type' => 'biginteger', 'null' => false),
            'tag_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'tag_collection_id' => array('column' => array('tag_collection_id')),
            'tag_id' => array('column' => array('tag_id')),
        ),
        'retired' => array(),
    );
}
