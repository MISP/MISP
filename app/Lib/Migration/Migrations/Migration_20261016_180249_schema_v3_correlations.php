<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Schema modernisation: drop correlations
 */
class Migration_20261016_180249_schema_v3_correlations extends AbstractMigration
{
    public $description = 'Schema modernisation: drop correlations';

    /**
     * Unused: the correlation engine before 2.4.160 kept its rows here; the
     * engines since keep theirs in default_correlations and no_acl_correlations.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('correlations')) {
            $schema->dropTable('correlations');
        }
    }
}
