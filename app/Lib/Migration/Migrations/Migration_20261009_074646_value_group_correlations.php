<?php

App::uses('AbstractMigration', 'Migration');
App::uses('TableConverger', 'Migration');
require_once __DIR__ . '/Migration_20261016_180202_schema_v3_default_correlations.php';
require_once __DIR__ . '/Migration_20261016_180203_schema_v3_no_acl_correlations.php';

/**
 * Key correlations by attribute value group, the tables emptied for the recorrelation after the upgrade
 */
class Migration_20261009_074646_value_group_correlations extends AbstractMigration
{
    public $description = 'Key correlations by attribute value group, the tables emptied for the recorrelation after the upgrade';

    public $requiresLogout = false;

    const TARGETS = array(
        'default_correlations' => Migration_20261016_180202_schema_v3_default_correlations::TARGET,
        'no_acl_correlations' => Migration_20261016_180203_schema_v3_no_acl_correlations::TARGET,
    );

    /**
     * Both are emptied and created at their 3.0 targets, keyed by value
     * group from the start, so the remap finds nothing to rewrite and the
     * full recorrelation after the upgrade refills them. correlation_values
     * stays until the gated text drop removes it. A table already at its
     * target is left alone, so a retry declares only what is left.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        foreach (self::TARGETS as $table => $target) {
            TableConverger::recreate($inspector, $schema, $table, $target, TableConverger::session($inspector));
        }
    }
}
