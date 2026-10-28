<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add the complex query role permission, granted to no role
 */
class Migration_20261028_065415_roles_perm_complex_query extends AbstractMigration
{
    public $description = 'Add the complex query role permission, granted to no role';

    /**
     * The role's permissions are part of the session, so every user picks
     * the new flag up by logging in again.
     *
     * @var bool
     */
    public $requiresLogout = true;

    /**
     * roles.perm_complex_query gates the boolean `query` tree of restSearch.
     * No role is granted it, admin roles included; it is opted in by hand.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('roles', 'perm_complex_query')) {
            return;
        }
        $schema->table('roles')->addColumn('perm_complex_query', 'boolean', array(
            'null' => false,
            'default' => 0,
        ));
    }
}
