<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Give bruteforces, system_settings and attr_value_counts an auto-increment id
 */
class Migration_20260909_175232_add_id_to_keyless_tables extends AbstractMigration
{
    public $description = 'Give bruteforces, system_settings and attr_value_counts an auto-increment id';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * Every MISP table has an auto-increment `id` as its primary key. These
     * three did not: bruteforces had no key at all, and system_settings and
     * attr_value_counts were keyed on the natural column they are looked up
     * by. Nothing in the application needed the id - but CakePHP asks the
     * driver for the inserted id after every save(), and while MySQL answers 0
     * for a table with no auto-increment, PostgreSQL's driver asks a sequence
     * by name and errors when there is none. The datasource now tolerates
     * that; this removes the exception.
     *
     * For the two natural keys the order matters: the unique index over the
     * old key column comes first, so the column is never unconstrained, then
     * the primary key constraint goes, then the id arrives carrying the new
     * one. system_settings keeps `setting` as the *model's* primary key, and
     * the upsert Correlation::generateTopOnDemand() runs infers its conflict
     * target from the unique index, so both keep working as they did.
     *
     * Each table is guarded: a re-run after a partial failure declares only
     * what is still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $tables = array(
            'bruteforces' => null,
            'system_settings' => 'setting',
            'attr_value_counts' => 'value',
        );
        foreach ($tables as $table => $naturalKey) {
            if (!$inspector->hasTable($table) || $inspector->hasColumn($table, 'id')) {
                continue;
            }
            $t = $schema->table($table);
            if ($naturalKey !== null) {
                if (!$inspector->hasIndex($table, $naturalKey, true, false)) {
                    $t->addIndex($naturalKey, array('unique' => true));
                }
                if ($inspector->primaryKey($table) !== array()) {
                    $t->dropPrimaryKey();
                }
            }
            $t->addColumn('id', 'primary_key', array('first' => true));
        }
    }
}
