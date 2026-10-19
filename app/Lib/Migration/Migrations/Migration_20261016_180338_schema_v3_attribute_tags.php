<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');

/**
 * Schema modernisation: attribute_tags
 */
class Migration_20261016_180338_schema_v3_attribute_tags extends TableMigration
{
    public $description = 'Schema modernisation: attribute_tags';

    const TABLE = 'attribute_tags';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'attribute_id' => array('type' => 'biginteger', 'null' => false),
            'event_id' => array('type' => 'biginteger', 'null' => false),
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
            'idx_attr_tags_attr_tag' => array('column' => array('attribute_id', 'tag_id')),
            'idx_attr_tags_event_tag' => array('column' => array('event_id', 'tag_id')),
            'tag_id' => array('column' => array('tag_id')),
        ),
        'retired' => array('attribute_id', 'event_id'),
    );
}
