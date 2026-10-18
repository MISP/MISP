<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Remember which revision of a shipped analyst profile MISP wrote itself
 */
class Migration_20261018_174227_analyst_profiles_shipped_revision extends AbstractMigration
{
    public $description = 'Remember which revision of a shipped analyst profile MISP wrote itself';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * The revision MISP last wrote to a shipped profile, so "edited here"
     * stops being true of every shipped profile once MISP has updated it.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasColumn('analyst_profiles', 'shipped_revision')) {
            return;
        }
        $schema->table('analyst_profiles')
            ->addColumn('shipped_revision', 'integer', array(
                'null' => true, 'default' => null, 'after' => 'revision',
            ));
    }

    /**
     * Rows still identical to their shipped file get the revision they carry;
     * the rest stay unknown, which reads as edited.
     *
     * @return bool
     */
    public function afterUp()
    {
        $AnalystProfile = ClassRegistry::init('AnalystProfile');
        $AnalystProfile->schema(true);
        $AnalystProfile->recordShippedRevisions();
        return true;
    }
}
