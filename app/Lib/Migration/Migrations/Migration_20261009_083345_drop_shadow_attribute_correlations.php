<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Drop shadow_attribute_correlations: proposal correlation is removed
 */
class Migration_20261009_083345_drop_shadow_attribute_correlations extends AbstractMigration
{
    public $description = 'Drop shadow_attribute_correlations: proposal correlation is removed';

    public $requiresLogout = false;

    /**
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('shadow_attribute_correlations')) {
            $schema->dropTable('shadow_attribute_correlations');
        }
    }
}
