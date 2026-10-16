<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: sightings
 */
class Migration_20261016_180334_schema_v3_sightings extends TableMigration
{
    public $description = 'Schema modernisation: sightings';

    const TABLE = 'sightings';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'attribute_id' => array('type' => 'biginteger', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'date_sighting' => array('type' => 'biginteger', 'null' => false),
            'uuid' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => '',
                'collate' => Collation::ASCII,
            ),
            'source' => array(
                'type' => 'string',
                'length' => 255,
                'null' => true,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'type' => array('type' => 'integer', 'null' => true, 'default' => '0'),
        ),
        'indexes' => array(
            'attribute_id' => array('column' => array('attribute_id')),
            'event_id' => array('column' => array('event_id')),
            'org_id' => array('column' => array('org_id')),
            'source' => array('column' => array('source')),
            'type' => array('column' => array('type')),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
