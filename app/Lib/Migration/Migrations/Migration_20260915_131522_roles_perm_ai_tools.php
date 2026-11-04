<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add the AI tools role permission, granted to site admins
 */
class Migration_20260915_131522_roles_perm_ai_tools extends AbstractMigration
{
    public $description = 'Add the AI tools role permission, granted to site admins';

    /**
     * The role's permissions are part of the session, so every user picks
     * the new flag up by logging in again.
     *
     * @var bool
     */
    public $requiresLogout = true;

    /**
     * roles.perm_ai_tools gates the AI actions - indicator extraction, report
     * summaries, tag suggestions. Guarded: an instance that gained the column
     * through legacy update 161 declares nothing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('roles', 'perm_ai_tools')) {
            return;
        }
        $schema->table('roles')->addColumn('perm_ai_tools', 'boolean', array(
            'null' => false,
            'default' => 0,
        ));
    }

    /**
     * Site admins get the permission on arrival, so the feature is reachable
     * the moment the upgrade lands; every other role is opted in by hand.
     * updateAll() rather than save(): Role::beforeSave() derives the perm_*
     * flags from the permission level and would rewrite them, and the
     * datasource renders the boolean for its own engine. Idempotent.
     *
     * @return bool
     */
    public function afterUp()
    {
        $Role = ClassRegistry::init('Role');
        $Role->schema(true);
        return $Role->updateAll(
            array('Role.perm_ai_tools' => true),
            array('Role.perm_site_admin' => true)
        ) !== false;
    }
}
