<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Index objects on (event_id, deleted), so counting an event's live objects reads only the index
 */
class Migration_20261013_091134_objects_event_deleted extends AbstractMigration
{
    public $description = 'Index objects on (event_id, deleted), so counting an event\'s live objects reads only the index';

    public $requiresLogout = false;

    /**
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $columns = array('event_id', 'deleted');
        if (!$this->inspector()->hasIndex('objects', $columns)) {
            $schema->table('objects')->addIndex($columns, array('name' => 'idx_event_deleted'));
        }
    }
}
