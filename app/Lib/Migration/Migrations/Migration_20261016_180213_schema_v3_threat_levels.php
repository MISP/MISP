<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: threat_levels
 */
class Migration_20261016_180213_schema_v3_threat_levels extends TableMigration
{
    public $description = 'Schema modernisation: threat_levels';

    const TABLE = 'threat_levels';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 50, 'null' => false, 'collate' => Collation::CI),
            'description' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
            'form_description' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'collate' => Collation::CI,
            ),
        ),
        'indexes' => array(),
        'retired' => array(),
    );
}
