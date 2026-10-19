<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: bruteforces
 */
class Migration_20261016_180207_schema_v3_bruteforces extends TableMigration
{
    public $description = 'Schema modernisation: bruteforces';

    const TABLE = 'bruteforces';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'ip' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'username' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'expire' => array('type' => 'datetime', 'null' => false),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
