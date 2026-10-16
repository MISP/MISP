<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: cryptographic_keys
 */
class Migration_20261016_180308_schema_v3_cryptographic_keys extends TableMigration
{
    public $description = 'Schema modernisation: cryptographic_keys';

    const TABLE = 'cryptographic_keys';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'type' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::BIN),
            'timestamp' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'parent_id' => array('type' => 'biginteger', 'null' => false),
            'parent_type' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::BIN),
            'key_data' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'revoked' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'fingerprint' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::ASCII,
            ),
        ),
        'indexes' => array(
            'fingerprint' => array('column' => array('fingerprint')),
            'parent_id' => array('column' => array('parent_id')),
            'parent_type' => array('column' => array('parent_type')),
            'type' => array('column' => array('type')),
            'uuid' => array('column' => array('uuid')),
        ),
        'retired' => array(),
    );
}
