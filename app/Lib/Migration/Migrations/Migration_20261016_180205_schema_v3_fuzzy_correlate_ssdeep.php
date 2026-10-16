<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: fuzzy_correlate_ssdeep
 */
class Migration_20261016_180205_schema_v3_fuzzy_correlate_ssdeep extends TableMigration
{
    public $description = 'Schema modernisation: fuzzy_correlate_ssdeep';

    const TABLE = 'fuzzy_correlate_ssdeep';

    const RECREATE = true;

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'chunk' => array('type' => 'string', 'length' => 12, 'null' => false, 'collate' => Collation::CI),
            'attribute_id' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'attribute_id' => array('column' => array('attribute_id')),
            'chunk' => array('column' => array('chunk')),
        ),
        'retired' => array(),
    );
}
