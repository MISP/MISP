<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Index objects on (event_id, deleted, name), so reading one template's objects of an event stays within that template
 */
class Migration_20261013_154619_objects_event_deleted_name extends AbstractMigration
{
    public $description = 'Index objects on (event_id, deleted, name), so reading one template\'s objects of an event stays within that template';

    public $requiresLogout = false;

    /**
     * The index is part of the objects 3.0 target, built in that table's
     * schema v3 rebuild rather than in a pass of its own.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }
}
