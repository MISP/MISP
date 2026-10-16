<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: noticelists
 */
class Migration_20261016_180229_schema_v3_noticelists extends TableMigration
{
    public $description = 'Schema modernisation: noticelists';

    const TABLE = 'noticelists';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'expanded_name' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'ref' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'geographical_area' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'collate' => Collation::CI,
            ),
            'version' => array('type' => 'integer', 'null' => false, 'default' => '1'),
            'enabled' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'geographical_area' => array('column' => array('geographical_area')),
            'name' => array('column' => array('name')),
        ),
        'retired' => array(),
    );
}
