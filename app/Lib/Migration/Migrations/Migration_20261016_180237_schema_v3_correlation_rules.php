<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: correlation_rules
 */
class Migration_20261016_180237_schema_v3_correlation_rules extends TableMigration
{
    public $description = 'Schema modernisation: correlation_rules';

    const TABLE = 'correlation_rules';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::BIN),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'selector_type' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::BIN),
            'selector_list' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
            'created' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
            'selector_type' => array('column' => array('selector_type')),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
