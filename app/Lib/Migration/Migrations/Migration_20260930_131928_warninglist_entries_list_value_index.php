<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Index warninglist_entries on (warninglist_id, value)
 */
class Migration_20260930_131928_warninglist_entries_list_value_index extends AbstractMigration
{
    public $description = 'Index warninglist_entries on (warninglist_id, value)';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * `Warninglist::assignComments()` looked an entry's comment up by value
     * with only `warninglist_id` indexed, scanning the whole matched list:
     * 64 ms and 126,004 rows to fetch one comment from the 62,745-entry
     * public resolver list, against 0.23 ms and one row with this index
     * (prd/analyst-profile/11-restsearch.md §3.5). Was legacy update 162 on
     * the personas branches.
     *
     * 191 characters of prefix: utf8mb3's 767-byte limit, and longer than any
     * entry on a shipped list. PostgreSQL has no prefix index; the dry run
     * reports what it renders instead.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasNamedIndex('warninglist_entries', 'idx_wle_list_value')) {
            return;
        }
        $schema->table('warninglist_entries')->addIndex(
            array('warninglist_id', 'value'),
            array('name' => 'idx_wle_list_value', 'length' => array('value' => 191))
        );
    }
}
