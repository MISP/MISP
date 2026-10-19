<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: attachment_scans
 */
class Migration_20261016_180214_schema_v3_attachment_scans extends TableMigration
{
    public $description = 'Schema modernisation: attachment_scans';

    const TABLE = 'attachment_scans';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'type' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::BIN),
            'attribute_id' => array('type' => 'biginteger', 'null' => false),
            'infected' => array('type' => 'boolean', 'null' => false),
            'malware_name' => array('type' => 'string', 'length' => 191, 'null' => true, 'collate' => Collation::CI),
            'timestamp' => array('type' => 'biginteger', 'null' => false),
        ),
        'indexes' => array(
            'index' => array('column' => array('type', 'attribute_id')),
        ),
        'retired' => array(),
    );
}
