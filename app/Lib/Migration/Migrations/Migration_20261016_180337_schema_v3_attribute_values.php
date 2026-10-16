<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: attribute_values
 */
class Migration_20261016_180337_schema_v3_attribute_values extends TableMigration
{
    public $description = 'Schema modernisation: attribute_values';

    const TABLE = 'attribute_values';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'hash' => array('type' => 'varbinary', 'length' => 32, 'null' => false),
        ),
        'indexes' => array(
            'hash' => array('column' => array('hash'), 'unique' => true),
            'value' => array(
                'column' => array('value'),
                'length' => array('value' => 128),
                'pgsql' => array(
                    'name' => 'idx_attribute_values_value',
                    'sql' => 'CREATE INDEX %1$s ON %2$s (lower(left("value", 128)));',
                ),
            ),
            'value_search' => array(
                'column' => array('value'),
                'fulltext' => true,
                'pgsql' => array(
                    'name' => 'idx_attribute_values_value_search',
                    'sql' => 'CREATE INDEX %1$s ON %2$s USING gin ("value" gin_trgm_ops);',
                    'extension' => 'pg_trgm',
                ),
            ),
        ),
        'retired' => array(),
    );
}
