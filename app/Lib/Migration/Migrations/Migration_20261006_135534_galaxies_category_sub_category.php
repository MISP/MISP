<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add category and sub-category to galaxies
 */
class Migration_20261006_135534_galaxies_category_sub_category extends AbstractMigration
{
    public $description = 'Add category and sub-category to galaxies';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * What a galaxy's clusters represent, ingested from the galaxy
     * definition. `namespace` groups by
     * publisher and `type` is an identifier, so a consumer asking "do these
     * name a threat?" had to hardcode galaxy names. Both nullable: absent
     * means nobody has classified this galaxy. `__load_galaxies` saves what
     * the definition carries, so ingestion needs no further code. No index -
     * the table is ~135 rows.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $galaxies = $schema->table('galaxies');
        if (!$inspector->hasColumn('galaxies', 'category')) {
            $galaxies->addColumn('category', 'string', array(
                'length' => 255, 'null' => true, 'default' => null, 'after' => 'namespace',
            ));
        }
        if (!$inspector->hasColumn('galaxies', 'sub_category')) {
            $galaxies->addColumn('sub_category', 'string', array(
                'length' => 255, 'null' => true, 'default' => null, 'after' => 'category',
            ));
        }
    }
}
