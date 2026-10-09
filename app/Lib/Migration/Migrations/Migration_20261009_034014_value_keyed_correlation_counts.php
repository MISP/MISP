<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Key over_correlating_values and attr_value_counts by attribute value id
 */
class Migration_20261009_034014_value_keyed_correlation_counts extends AbstractMigration
{
    public $description = 'Key over_correlating_values and attr_value_counts by attribute value id';

    public $requiresLogout = false;

    /**
     * over_correlating_values keeps its text key beside the id for now: the
     * Default and NoAcl engines still compare it with correlation_values.
     * attr_value_counts is a cache the OnDemand top list regenerates, so it
     * is recreated empty in its new shape. Guarded, so a retry after a
     * partial failure declares only what is still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $overCorrelating = $schema->table('over_correlating_values');
        if (!$inspector->hasColumn('over_correlating_values', 'value_id')) {
            $overCorrelating->addColumn('value_id', 'biginteger', array(
                'unsigned' => true,
                'null' => true,
                'default' => null,
                'after' => 'id',
            ));
        }
        if (!$inspector->hasIndex('over_correlating_values', 'value_id', true)) {
            $overCorrelating->addIndex('value_id', array('unique' => true));
        }

        if ($inspector->hasTable('attr_value_counts')) {
            if ($inspector->hasColumn('attr_value_counts', 'value_id')) {
                return;
            }
            $schema->dropTable('attr_value_counts');
        }
        $schema->createTable('attr_value_counts', array(
            'id' => array('type' => 'biginteger', 'key' => 'primary', 'unsigned' => true, 'null' => false),
            'value_id' => array('type' => 'biginteger', 'unsigned' => true, 'null' => false),
            'cnt_v1' => array('type' => 'biginteger', 'unsigned' => true, 'null' => false, 'default' => 0),
            'cnt_v2' => array('type' => 'biginteger', 'unsigned' => true, 'null' => false, 'default' => 0),
        ), array(
            'indexes' => array(
                'value_id' => array('unique' => true),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
        ));
    }

    /**
     * A stored over-correlating value the dictionary does not hold yet keeps
     * a null id until a later remap finds it.
     *
     * @return bool
     */
    public function afterUp()
    {
        $OverCorrelatingValue = ClassRegistry::init('OverCorrelatingValue');
        $OverCorrelatingValue->schema(true);
        $OverCorrelatingValue->remapValueIds();
        return true;
    }
}
