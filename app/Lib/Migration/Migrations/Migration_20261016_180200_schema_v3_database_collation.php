<?php

App::uses('AbstractMigration', 'Migration');
App::uses('Collation', 'Migration');

/**
 * Schema modernisation: database default collation
 */
class Migration_20261016_180200_schema_v3_database_collation extends AbstractMigration
{
    public $description = 'Schema modernisation: database default collation';

    /**
     * A table created without a collation of its own takes the database's.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->alterDatabase(array('collate' => Collation::CI));
    }
}
