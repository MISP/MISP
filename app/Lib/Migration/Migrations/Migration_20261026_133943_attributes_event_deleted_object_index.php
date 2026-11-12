<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add a composite index on attributes (event_id, deleted, object_id)
 */
class Migration_20261026_133943_attributes_event_deleted_object_index extends AbstractMigration
{
    public $description = 'Add a composite index on attributes (event_id, deleted, object_id)';

    /**
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * The per-event attribute count on the event index filters on event_id,
     * deleted and object_id, which no existing index covers together.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $columns = array('event_id', 'deleted', 'object_id');
        if (!$this->inspector()->hasIndex('attributes', $columns)) {
            $schema->table('attributes')
                ->addIndex($columns, array('name' => 'idx_attr_event_deleted_object'));
        }
    }
}
