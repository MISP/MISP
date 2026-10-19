<?php

App::uses('AbstractMigration', 'Migration');
require_once __DIR__ . '/Migration_20261016_180317_schema_v3_shadow_attributes.php';
require_once __DIR__ . '/Migration_20261016_180339_schema_v3_attributes.php';

/**
 * Add nullable value id columns to attributes and shadow_attributes, and the
 * attribute creation time
 */
class Migration_20261004_093749_attribute_value_ids extends AbstractMigration
{
    public $description = 'Add nullable value id columns to attributes and shadow_attributes, and the attribute creation time';

    public $requiresLogout = false;

    /**
     * The columns as the 3.0 targets define them. Their indexes are built by
     * the schema v3 migrations' rebuild of each table; the backfill reads by
     * primary key and needs none of them. Guarded, so a retry after a partial
     * failure declares only what is still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $targets = array(
            'attributes' => Migration_20261016_180339_schema_v3_attributes::TARGET,
            'shadow_attributes' => Migration_20261016_180317_schema_v3_shadow_attributes::TARGET,
        );
        foreach ($targets as $tableName => $target) {
            $columns = array('value1_id' => 'value2', 'value2_id' => 'value1_id');
            if ($tableName === 'attributes') {
                $columns['created'] = 'timestamp';
            }
            $table = $schema->table($tableName);
            foreach ($columns as $column => $after) {
                if (!$inspector->hasColumn($tableName, $column)) {
                    $spec = $target['columns'][$column];
                    unset($spec['type']);
                    $table->addColumn($column, $target['columns'][$column]['type'], $spec + array('after' => $after));
                }
            }
        }
    }
}
