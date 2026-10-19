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
     * The index is part of the warninglist_entries 3.0 target, built in that
     * table's schema v3 rebuild rather than in a pass of its own.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }
}
