<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Index attributes on (event_id, deleted, object_id), so an event's live loose attributes are read without its deleted rows
 */
class Migration_20261013_070812_attributes_event_deleted_object extends AbstractMigration
{
    public $description = 'Index attributes on (event_id, deleted, object_id), so an event\'s live loose attributes are read without its deleted rows';

    public $requiresLogout = false;

    /**
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $columns = array('event_id', 'deleted', 'object_id');
        if (!$this->inspector()->hasIndex('attributes', $columns)) {
            $schema->table('attributes')->addIndex($columns, array('name' => 'idx_event_deleted_object'));
        }
    }
}
