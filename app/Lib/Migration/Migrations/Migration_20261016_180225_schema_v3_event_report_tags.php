<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_report_tags
 */
class Migration_20261016_180225_schema_v3_event_report_tags extends TableMigration
{
    public $description = 'Schema modernisation: event_report_tags';

    const TABLE = 'event_report_tags';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'event_report_id' => array('type' => 'biginteger', 'null' => false),
            'tag_id' => array('type' => 'biginteger', 'null' => false),
            'local' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'relationship_type' => array(
                'type' => 'string',
                'length' => 191,
                'null' => true,
                'default' => '',
                'collate' => Collation::CI,
            ),
        ),
        'indexes' => array(
            'event_report_id' => array('column' => array('event_report_id')),
            'tag_id' => array('column' => array('tag_id')),
        ),
        'retired' => array(),
    );
}
