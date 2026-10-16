<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_template_object_dependencies
 */
class Migration_20261016_180226_schema_v3_event_template_object_dependencies extends TableMigration
{
    public $description = 'Schema modernisation: event_template_object_dependencies';

    const TABLE = 'event_template_object_dependencies';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'event_template_id' => array('type' => 'biginteger', 'null' => false),
            'object_template_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => false,
                'collate' => Collation::ASCII,
            ),
            'object_template_name' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'collate' => Collation::CI,
            ),
            'minimum_version' => array('type' => 'integer', 'unsigned' => true, 'null' => false),
        ),
        'indexes' => array(
            'event_template_id' => array('column' => array('event_template_id')),
            'object_template_uuid' => array('column' => array('object_template_uuid')),
        ),
        'retired' => array(),
    );
}
