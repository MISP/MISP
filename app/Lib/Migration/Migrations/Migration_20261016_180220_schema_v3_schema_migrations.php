<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: schema_migrations
 */
class Migration_20261016_180220_schema_v3_schema_migrations extends TableMigration
{
    public $description = 'Schema modernisation: schema_migrations';

    const TABLE = 'schema_migrations';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'migration_id' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => Collation::CI),
            'applied_at' => array('type' => 'datetime', 'null' => false),
            'duration_ms' => array('type' => 'integer', 'null' => false, 'default' => '0'),
            'status' => array(
                'type' => 'string',
                'length' => 16,
                'null' => false,
                'default' => 'applied',
                'collate' => Collation::CI,
            ),
            'error' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
        ),
        'indexes' => array(
            'migration_id' => array('column' => array('migration_id'), 'unique' => true),
        ),
        'retired' => array(),
    );
}
