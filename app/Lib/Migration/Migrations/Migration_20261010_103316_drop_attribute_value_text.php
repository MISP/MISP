<?php

App::uses('AbstractMigration', 'Migration');
App::uses('AttributeValueBackfillTool', 'Tools');
App::uses('CorrelationRemapTool', 'Tools');

/**
 * Drop the value text columns of attributes and proposals
 */
class Migration_20261010_103316_drop_attribute_value_text extends AbstractMigration
{
    public $description = 'Drop the value text columns of attributes and proposals, and correlation_values: values live in attribute_values';

    public $requiresLogout = false;

    const TABLES = ['attributes', 'shadow_attributes'];

    const TEXT = ['value1', 'value2'];

    /**
     * The text goes for good, so this refuses until every row's ids give back
     * its text and every correlation is keyed by value group. A refusal counts
     * as a failed update, and runUpdates resets that count.
     *
     * @return bool
     * @throws RuntimeException With the command that puts it right.
     */
    public function beforeUp()
    {
        $inspector = $this->inspector();
        $AttributeValue = ClassRegistry::init('AttributeValue');
        $backfill = new AttributeValueBackfillTool($AttributeValue);
        foreach (self::TABLES as $table) {
            if (!$inspector->hasColumn($table, 'value1') || !$inspector->hasColumn($table, 'value2')) {
                continue;
            }
            $counts = $backfill->verify($table);
            if ($counts['pending'] > 0) {
                throw new RuntimeException(sprintf(
                    '%d rows of %s have no value ids yet: run `cake AttributeValue backfill`, then `cake Admin runUpdates`.',
                    $counts['pending'],
                    $table
                ));
            }
            if ($counts['mismatched'] > 0) {
                throw new RuntimeException(sprintf(
                    '%d rows of %s have value ids that do not give back their text (first id %d): set their value1_id and value2_id to NULL, run `cake AttributeValue backfill`, then `cake Admin runUpdates`.',
                    $counts['mismatched'],
                    $table,
                    $counts['first_mismatch']
                ));
            }
        }
        if (!(new CorrelationRemapTool($AttributeValue))->done()) {
            throw new RuntimeException('Some correlations are still keyed by correlation_values: run `cake AttributeValue remapCorrelations`, then `cake Admin runUpdates`.');
        }
        if ($inspector->hasColumn('over_correlating_values', 'value')) {
            $OverCorrelatingValue = ClassRegistry::init('OverCorrelatingValue');
            $OverCorrelatingValue->remapValueIds();
            // Blocks are read by value id only, so a row still without one blocks nothing
            $OverCorrelatingValue->deleteAll(['OverCorrelatingValue.value_id' => null], false);
        }
        return true;
    }

    /**
     * Every index naming a text column goes first: MySQL would keep the rest
     * of a multi-column index. Guarded, so a retry declares only what is left.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        foreach (self::TABLES as $table) {
            $text = array_values(array_filter(self::TEXT, function ($column) use ($inspector, $table) {
                return $inspector->hasColumn($table, $column);
            }));
            if (empty($text)) {
                continue;
            }
            $builder = $schema->table($table);
            foreach ($inspector->indexes($table) as $name => $index) {
                if ($name !== 'PRIMARY' && array_intersect((array)$index['column'], $text)) {
                    $builder->dropIndex($name);
                }
            }
            foreach ($text as $column) {
                $builder->dropColumn($column);
            }
        }
        if ($inspector->hasTable('correlation_values')) {
            $schema->dropTable('correlation_values');
        }
        if ($inspector->hasColumn('over_correlating_values', 'value')) {
            $schema->table('over_correlating_values')->dropColumn('value');
        }
    }
}
