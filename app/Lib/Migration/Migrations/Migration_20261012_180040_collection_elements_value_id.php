<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Let a collection Value element point at the value dictionary
 */
class Migration_20261012_180040_collection_elements_value_id extends AbstractMigration
{
    public $description = 'Let a collection Value element point at the value dictionary';

    /**
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * Guarded, so a retry after a partial failure declares only what is
     * still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $table = $schema->table('collection_elements');
        if (!$inspector->hasColumn('collection_elements', 'value_id')) {
            $table->addColumn('value_id', 'biginteger', array(
                'unsigned' => true,
                'null' => true,
                'default' => null,
                'after' => 'element_type',
            ));
        }
        if (!$inspector->hasIndex('collection_elements', 'value_id')) {
            $table->addIndex('value_id');
        }
    }
}
