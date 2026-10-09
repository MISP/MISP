<?php

App::uses('AbstractMigration', 'Migration');
App::uses('CorrelationRemapTool', 'Tools');

/**
 * Key correlations by attribute value group; cake AttributeValue remapCorrelations moves the existing rows
 */
class Migration_20261009_074646_value_group_correlations extends AbstractMigration
{
    public $description = 'Key correlations by attribute value group; cake AttributeValue remapCorrelations moves the existing rows';

    public $requiresLogout = false;

    /**
     * correlation_values and the over-correlation text key stay until the
     * remap has read them; the gated text drop removes them. Guarded, so a
     * retry after a partial failure declares only what is still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        foreach (CorrelationRemapTool::TABLES as $table) {
            $column = $inspector->columns($table);
            if (isset($column['value_id']) && $column['value_id']['type'] !== 'biginteger') {
                $schema->table($table)->changeColumn('value_id', 'biginteger', array(
                    'unsigned' => true,
                    'null' => false,
                    'default' => null,
                ));
            }
        }
    }

    /**
     * The rows the tables hold now are the ones the remap rewrites; rows
     * written from here on are keyed by value group already.
     *
     * @return bool
     */
    public function afterUp()
    {
        $tool = new CorrelationRemapTool(ClassRegistry::init('AttributeValue'));
        foreach (CorrelationRemapTool::TABLES as $table) {
            $tool->recordBound($table);
        }
        return true;
    }
}
