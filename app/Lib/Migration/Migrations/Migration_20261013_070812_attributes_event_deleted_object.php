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
     * The index is part of the attributes 3.0 target, built in that table's
     * schema v3 rebuild rather than in a pass of its own.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }
}
