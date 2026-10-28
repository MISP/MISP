<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Record who added each collection element and when
 */
class Migration_20261028_090206_collection_element_provenance extends AbstractMigration
{
    public $description = 'Record who added each collection element and when';

    public $requiresLogout = false;

    /**
     * Both stay empty on the elements that exist already: nothing recorded
     * who added them or when.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('collection_elements')
            ->addColumn('user_id', 'biginteger', array(
                'null' => true,
                'default' => null,
                'after' => 'collection_id',
            ))
            ->addColumn('created', 'datetime', array(
                'null' => true,
                'default' => null,
                'after' => 'description',
            ));
    }
}
