<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_blocklists
 */
class Migration_20261016_180309_schema_v3_event_blocklists extends TableMigration
{
    public $description = 'Schema modernisation: event_blocklists';

    const TABLE = 'event_blocklists';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'event_uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'created' => array('type' => 'datetime', 'null' => false),
            'event_info' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'comment' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'event_orgc' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
        ),
        'indexes' => array(
            'event_orgc' => array('column' => array('event_orgc')),
            'event_uuid' => array('column' => array('event_uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
