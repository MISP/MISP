<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add nullable value id columns and their indexes to attributes and shadow_attributes,
 * and the attribute creation time
 */
class Migration_20261004_093749_attribute_value_ids extends AbstractMigration
{
    public $description = 'Add nullable value id columns and their indexes to attributes and shadow_attributes, and the attribute creation time';

    public $requiresLogout = false;

    /**
     * Named apart from the value1/value2 prefix indexes they will replace,
     * which share the canonical names while the text columns remain.
     */
    const ATTRIBUTE_INDEXES = array(
        'idx_attr_vid_combo' => array('value1_id', 'value2_id'),
        'idx_vid1_source' => array('event_id', 'value1_id', 'deleted', 'disable_correlation', 'type', 'id'),
        'idx_vid1_target' => array('value1_id', 'event_id', 'deleted', 'disable_correlation', 'type', 'id'),
        'idx_vid2_source' => array('event_id', 'value2_id', 'deleted', 'disable_correlation', 'type', 'id'),
        'idx_vid2_target' => array('value2_id', 'event_id', 'deleted', 'disable_correlation', 'type', 'id'),
    );

    /**
     * Guarded, so a retry after a partial failure declares only what is
     * still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        foreach (array('attributes', 'shadow_attributes') as $tableName) {
            $table = $schema->table($tableName);
            $after = 'value2';
            foreach (array('value1_id', 'value2_id') as $column) {
                if (!$inspector->hasColumn($tableName, $column)) {
                    $table->addColumn($column, 'biginteger', array(
                        'unsigned' => true,
                        'null' => true,
                        'default' => null,
                        'after' => $after,
                    ));
                }
                $after = $column;
            }
            // Declared here so it joins the value id columns' statement and the
            // index pass below, instead of costing a pass over attributes of its own.
            if ($tableName === 'attributes' && !$inspector->hasColumn('attributes', 'created')) {
                $table->addColumn('created', 'biginteger', array(
                    'null' => false,
                    'default' => 0,
                    'after' => 'timestamp',
                ));
            }
        }

        $shadowAttributes = $schema->table('shadow_attributes');
        foreach (array('value1_id', 'value2_id') as $column) {
            if (!$inspector->hasIndex('shadow_attributes', $column)) {
                $shadowAttributes->addIndex($column);
            }
        }
        $attributes = $schema->table('attributes');
        foreach (self::ATTRIBUTE_INDEXES as $name => $columns) {
            if (!$inspector->hasIndex('attributes', $columns)) {
                $attributes->addIndex($columns, array('name' => $name));
            }
        }
        if (!$inspector->hasIndex('attributes', array('created'))) {
            $attributes->addIndex('created');
        }
    }
}
