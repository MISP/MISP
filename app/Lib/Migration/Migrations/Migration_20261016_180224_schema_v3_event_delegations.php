<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_delegations
 */
class Migration_20261016_180224_schema_v3_event_delegations extends TableMigration
{
    public $description = 'Schema modernisation: event_delegations';

    const TABLE = 'event_delegations';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'requester_org_id' => array('type' => 'biginteger', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
            'message' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '-1'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
        ),
        'indexes' => array(
            'event_id' => array('column' => array('event_id')),
            'org_id' => array('column' => array('org_id')),
        ),
        'retired' => array(),
    );
}
