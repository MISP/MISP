<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Schema modernisation: drop tasks
 */
class Migration_20261016_180201_schema_v3_drop_tasks extends AbstractMigration
{
    public $description = 'Schema modernisation: drop tasks';

    /**
     * Unused: the Task model reads scheduled_tasks.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('tasks')) {
            $schema->dropTable('tasks');
        }
    }
}
