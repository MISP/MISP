<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Galaxies' distribution defaults to 0 at the database level
 */
class Migration_20261028_131434_galaxies_distribution_default extends AbstractMigration
{
    public $description = 'Galaxies\' distribution defaults to 0 at the database level';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * MISP always sets the value itself (the Galaxy model's default comes from
     * MISP.default_galaxy_distribution); this only covers rows inserted from
     * outside MISP, which stay with the owning organisation.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('galaxies')
            ->changeColumn('distribution', 'tinyinteger', array(
                'null' => false,
                'default' => 0,
            ));
    }
}
