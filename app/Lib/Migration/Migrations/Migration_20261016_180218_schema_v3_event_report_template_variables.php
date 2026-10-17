<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: event_report_template_variables
 */
class Migration_20261016_180218_schema_v3_event_report_template_variables extends TableMigration
{
    public $description = 'Schema modernisation: event_report_template_variables';

    const TABLE = 'event_report_template_variables';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'value' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'name' => array('column' => array('name')),
        ),
        'retired' => array(),
    );
}
