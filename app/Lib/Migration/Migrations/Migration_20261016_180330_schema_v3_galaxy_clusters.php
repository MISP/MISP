<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: galaxy_clusters
 */
class Migration_20261016_180330_schema_v3_galaxy_clusters extends TableMigration
{
    public $description = 'Schema modernisation: galaxy_clusters';

    const TABLE = 'galaxy_clusters';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'uuid' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::ASCII,
            ),
            'collection_uuid' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'collate' => Collation::ASCII,
            ),
            'type' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::BIN),
            'value' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'tag_name' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::CI,
            ),
            'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
            'galaxy_id' => array('type' => 'biginteger', 'null' => false),
            'source' => array(
                'type' => 'string',
                'length' => 255,
                'null' => false,
                'default' => '',
                'collate' => Collation::BIN,
            ),
            'authors' => array('type' => 'text', 'null' => false, 'collate' => Collation::BIN),
            'version' => array('type' => 'integer', 'null' => true, 'default' => '0'),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => true),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'orgc_id' => array('type' => 'biginteger', 'null' => false),
            'default' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'locked' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'extends_uuid' => array(
                'type' => 'string',
                'length' => 40,
                'null' => true,
                'default' => '',
                'collate' => Collation::ASCII,
            ),
            'extends_version' => array('type' => 'integer', 'null' => true, 'default' => '0'),
            'published' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'collection_uuid' => array('column' => array('collection_uuid')),
            'default' => array('column' => array('default')),
            'extends_uuid' => array('column' => array('extends_uuid')),
            'extends_version' => array('column' => array('extends_version')),
            'galaxy_id' => array('column' => array('galaxy_id')),
            'org_id' => array('column' => array('org_id')),
            'orgc_id' => array('column' => array('orgc_id')),
            'sharing_group_id' => array('column' => array('sharing_group_id')),
            'tag_name' => array('column' => array('tag_name')),
            'type' => array('column' => array('type')),
            'uuid' => array('column' => array('uuid')),
            'value' => array('column' => array('value'), 'length' => array('value' => 255)),
            'version' => array('column' => array('version')),
        ),
        'retired' => array(),
    );
}
