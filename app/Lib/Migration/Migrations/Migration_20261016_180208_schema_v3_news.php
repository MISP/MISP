<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: news
 */
class Migration_20261016_180208_schema_v3_news extends TableMigration
{
    public $description = 'Schema modernisation: news';

    const TABLE = 'news';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'message' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'title' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'user_id' => array('type' => 'biginteger', 'null' => false),
            'date_created' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
