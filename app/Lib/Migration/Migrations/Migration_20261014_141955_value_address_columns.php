<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Add SHA-256 address columns beside the uuid links of analyst data and collection elements
 */
class Migration_20261014_141955_value_address_columns extends AbstractMigration
{
    public $description = 'Add SHA-256 address columns beside the uuid links of analyst data and collection elements';

    public $requiresLogout = false;

    const ASCII = array('charset' => 'ascii', 'collate' => 'ascii_general_ci');

    /**
     * A row fills one address column of each pair, chosen by its type: the
     * uuid for everything except an attribute value, which is addressed by
     * the SHA-256 of its text.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $links = array(
            'notes' => array('object'),
            'opinions' => array('object'),
            'relationships' => array('object', 'related_object'),
        );
        foreach ($links as $tableName => $prefixes) {
            $table = $schema->table($tableName);
            foreach ($prefixes as $prefix) {
                $this->addAddress($table, $prefix . '_uuid', $prefix . '_sha256');
                $table->addIndex($prefix . '_sha256');
            }
        }

        $elements = $schema->table('collection_elements');
        $this->addAddress($elements, 'element_uuid', 'element_sha256');
        $elements->addIndex(array('element_sha256', 'collection_id'), array(
            'unique' => true,
            'name' => 'unique_element_sha256',
        ));
    }

    /**
     * @param SchemaTableBuilder $table
     * @param string $uuidColumn
     * @param string $sha256Column
     * @return void
     */
    private function addAddress(SchemaTableBuilder $table, $uuidColumn, $sha256Column)
    {
        $table->addColumn($sha256Column, 'string', array(
            'length' => 64,
            'null' => true,
            'default' => null,
            'after' => $uuidColumn,
        ) + self::ASCII);
        $table->changeColumn($uuidColumn, 'string', array(
            'length' => 40,
            'null' => true,
            'default' => null,
        ) + self::ASCII);
    }
}
