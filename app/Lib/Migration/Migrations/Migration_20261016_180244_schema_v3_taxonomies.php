<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: taxonomies
 */
class Migration_20261016_180244_schema_v3_taxonomies extends TableMigration
{
    public $description = 'Schema modernisation: taxonomies';

    const TABLE = 'taxonomies';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'namespace' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'description' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'version' => array('type' => 'integer', 'null' => false),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'exclusive' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
            'required' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'highlighted' => array('type' => 'boolean', 'null' => true, 'default' => '0'),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
