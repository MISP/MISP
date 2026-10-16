<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Create the analyst_graphs table
 */
class Migration_20261001_095359_analyst_graphs extends AbstractMigration
{
    public $description = 'Create the analyst_graphs table';

    /**
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * A graph is analyst data: the columns every analyst-data table shares,
     * then its own. `content` holds the graph document; `content_size` and
     * `node_count` are derived from it on save so listings and sync can size
     * a graph without loading it.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('analyst_graphs')) {
            return;
        }
        $ascii = array('charset' => 'ascii', 'collate' => 'ascii_general_ci');
        $schema->createTable('analyst_graphs', array(
            'id' => array('type' => 'primary_key'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false) + $ascii,
            'object_uuid' => array('type' => 'string', 'length' => 40, 'null' => false) + $ascii,
            'object_type' => array('type' => 'string', 'length' => 80, 'null' => false) + $ascii,
            'authors' => array('type' => 'text', 'null' => true, 'default' => null),
            'org_uuid' => array('type' => 'string', 'length' => 40, 'null' => false) + $ascii,
            'orgc_uuid' => array('type' => 'string', 'length' => 40, 'null' => false) + $ascii,
            'created' => array('type' => 'datetime', 'null' => false),
            'modified' => array('type' => 'datetime', 'null' => false),
            'distribution' => array('type' => 'tinyinteger', 'null' => false),
            'sharing_group_id' => array('type' => 'integer', 'null' => true, 'default' => null),
            'locked' => array('type' => 'boolean', 'null' => false, 'default' => 0),
            'name' => array('type' => 'string', 'length' => 191, 'null' => false),
            'description' => array('type' => 'text', 'null' => true, 'default' => null),
            'content' => array('type' => 'longtext', 'null' => false),
            'content_size' => array('type' => 'integer', 'null' => false, 'default' => 0),
            'node_count' => array('type' => 'integer', 'null' => false, 'default' => 0),
            'revision' => array('type' => 'integer', 'null' => false, 'default' => 1),
            'forked_from_uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'default' => null) + $ascii,
        ), array(
            'indexes' => array(
                'uuid' => array('unique' => true),
                'object_uuid' => array(),
                'object_type' => array(),
                'org_uuid' => array(),
                'orgc_uuid' => array(),
                'distribution' => array(),
                'sharing_group_id' => array(),
                'forked_from_uuid' => array(),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
            'collate' => 'utf8mb4_unicode_ci',
        ));
    }
}
