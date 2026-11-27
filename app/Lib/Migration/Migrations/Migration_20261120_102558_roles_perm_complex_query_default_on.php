<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Grant the complex query role permission to every role
 */
class Migration_20261120_102558_roles_perm_complex_query_default_on extends AbstractMigration
{
    public $description = 'Grant the complex query role permission to every role';

    /**
     * The role's permissions are part of the session, so every user picks
     * the flag up by logging in again.
     *
     * @var bool
     */
    public $requiresLogout = true;

    /**
     * The permission is an off switch for accounts that should not send
     * complex queries, so the column defaults to on.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('roles')
            ->changeColumn('perm_complex_query', 'boolean', array(
                'null' => false,
                'default' => 1,
            ));
    }

    /**
     * updateAll() rather than save(): Role::beforeSave() derives the perm_*
     * flags from the permission level and would rewrite them. The conditions
     * are true, not an empty array, which the MySQL datasource renders as
     * WHERE 0 = 1. Idempotent.
     *
     * @return bool
     */
    public function afterUp()
    {
        $Role = ClassRegistry::init('Role');
        $Role->schema(true);
        return $Role->updateAll(
            array('Role.perm_complex_query' => true),
            true
        ) !== false;
    }
}
