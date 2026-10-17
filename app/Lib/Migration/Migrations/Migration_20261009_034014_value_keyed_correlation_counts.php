<?php

App::uses('AbstractMigration', 'Migration');
App::uses('TableConverger', 'Migration');
require_once __DIR__ . '/Migration_20261016_180204_schema_v3_over_correlating_values.php';
require_once __DIR__ . '/Migration_20261016_180332_schema_v3_attr_value_counts.php';

/**
 * Key over_correlating_values and attr_value_counts by attribute value id
 */
class Migration_20261009_034014_value_keyed_correlation_counts extends AbstractMigration
{
    public $description = 'Key over_correlating_values and attr_value_counts by attribute value id';

    public $requiresLogout = false;

    const TARGETS = array(
        'over_correlating_values' => Migration_20261016_180204_schema_v3_over_correlating_values::TARGET,
        'attr_value_counts' => Migration_20261016_180332_schema_v3_attr_value_counts::TARGET,
    );

    /**
     * Both are emptied and created at their 3.0 targets: the full
     * recorrelation after the upgrade refills over_correlating_values, and
     * the OnDemand top list regenerates attr_value_counts. A table already
     * at its target is left alone, so a retry declares only what is left.
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

    /**
     * The remap step runUpgrade runs next reads the table through the model.
     *
     * @return bool
     */
    public function afterUp()
    {
        ClassRegistry::init('OverCorrelatingValue')->schema(true);
        return true;
    }
}
