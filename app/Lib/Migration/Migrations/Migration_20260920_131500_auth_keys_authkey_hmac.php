<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add the indexed keyed-hash lookup column for advanced auth keys
 */
class Migration_20260920_131500_auth_keys_authkey_hmac extends AbstractMigration
{
    public $description = 'Add the indexed keyed-hash lookup column for advanced auth keys';

    /**
     * auth_keys is not part of the session, so nobody has to log in again: the
     * column is read by AuthKey::getAuthUserByAuthKey() on the next request and
     * is NULL until that request backfills it.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * auth_keys.authkey_hmac holds hash_hmac('sha512', <authkey>, <hmac_key>)
     * so resolving an API key is one indexed equality lookup instead of a
     * bcrypt verify per row sharing the 4+4-character prefix pair. The bcrypt
     * column and its verification loop are untouched and remain the fallback:
     * every pre-existing row is NULL here until its owner's next request
     * backfills it, and a missing or rotated hmac_key.php simply misses the
     * index and falls back, never accepts.
     *
     * A plain index, not a unique one. AuthKey::beforeValidate() accepts a
     * caller-supplied authkey, and the column is NULL for every row that has
     * not been backfilled yet, so uniqueness is not something this column can
     * promise. Equality is all the lookup asks of it.
     *
     * 128 characters because sha512 renders as 128 hex digits; ascii because
     * that is the alphabet, matching the neighbouring authkey columns.
     *
     * Guarded: an instance that gained the column some other way declares
     * nothing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('auth_keys', 'authkey_hmac')) {
            return;
        }
        $schema->table('auth_keys')
            ->addColumn('authkey_hmac', 'string', array(
                'length' => 128,
                'null' => true,
                'default' => null,
                'charset' => 'ascii',
                'collate' => 'ascii_general_ci',
                'after' => 'authkey_end',
            ))
            ->addIndex('authkey_hmac');
    }
}
