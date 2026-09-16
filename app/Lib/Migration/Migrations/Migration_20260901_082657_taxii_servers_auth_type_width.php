<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Narrow taxii_servers.auth_type to varchar(191) utf8mb4
 */
class Migration_20260901_082657_taxii_servers_auth_type_width extends AbstractMigration
{
    public $description = 'Narrow taxii_servers.auth_type to varchar(191) utf8mb4';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * auth_type was added as VARCHAR(255) with no charset of its own, so it
     * inherited the table's utf8mb4 - 255 characters of it, which InnoDB cannot
     * index at all under the 767-byte prefix limit. 191 is the width the rest of
     * this table already uses for exactly that reason, and the column holds
     * 'basic' or 'bearer'.
     *
     * The charset and collation are restated rather than left implicit: they are
     * already what this asks for on a stock instance, but an instance whose
     * taxii_servers was created under a different table default would otherwise
     * keep it. Naming the collation matters - asking for utf8mb4 alone would let
     * the server pick its default collation, which is not the utf8mb4_unicode_ci
     * the neighbouring columns use.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('taxii_servers')
            ->changeColumn('auth_type', 'string', array(
                'length' => 191,
                'null' => true,
                'default' => 'basic',
                'charset' => 'utf8mb4',
                'collate' => 'utf8mb4_unicode_ci',
            ));
    }
}
