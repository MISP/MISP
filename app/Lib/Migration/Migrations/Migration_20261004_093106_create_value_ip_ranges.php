<?php

App::uses('AbstractMigration', 'Migration');
App::uses('TableConverger', 'Migration');
require_once __DIR__ . '/Migration_20261016_180329_schema_v3_value_ip_ranges.php';

/**
 * Create the value_ip_ranges IP facet of attribute_values
 */
class Migration_20261004_093106_create_value_ip_ranges extends AbstractMigration
{
    public $description = 'Create the value_ip_ranges IP facet of attribute_values';

    public $requiresLogout = false;

    const TABLE = 'value_ip_ranges';

    /**
     * IPv4 is stored v4-mapped, so both ends are always 16 bytes. value_id
     * closes start_end so that range lookups return it from the index alone.
     *
     * Created at the 3.0 target, which its schema v3 migration then finds
     * met. Converged, so a retry after a partial failure declares only what
     * is still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        TableConverger::converge(
            $inspector,
            $schema,
            self::TABLE,
            Migration_20261016_180329_schema_v3_value_ip_ranges::TARGET,
            TableConverger::session($inspector)
        );
    }
}
