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
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $columns = array('event_id', 'deleted', 'name');
        if (!$this->inspector()->hasIndex('objects', $columns)) {
            $schema->table('objects')->addIndex($columns, array('name' => 'idx_event_deleted_name'));
        }
    }
}
