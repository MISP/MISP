<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: warninglists
 */
class Migration_20261016_180256_schema_v3_warninglists extends TableMigration
{
    public $description = 'Schema modernisation: warninglists';

    const TABLE = 'warninglists';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'type' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => 'string',
                'collate' => Collation::BIN,
            ),
            'description' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'version' => array('type' => 'integer', 'null' => false, 'default' => '1'),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
            'category' => array(
                'type' => 'string',
                'length' => 20,
                'null' => false,
                'default' => 'false_positive',
                'collate' => Collation::CI,
            ),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
