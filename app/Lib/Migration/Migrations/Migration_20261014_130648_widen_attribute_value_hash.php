<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Key attribute_values by the whole SHA-256 of the value
 */
class Migration_20261014_130648_widen_attribute_value_hash extends AbstractMigration
{
    public $description = 'Key attribute_values by the whole SHA-256 of the value';

    public $requiresLogout = false;

    const CHUNK = 50000;

    /**
     * Only a dictionary built before its key grew from 16 to 32 bytes has
     * anything to change: the create migration now makes 32 directly.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('attribute_values')->changeColumn('hash', 'varbinary', array(
            'length' => 32,
            'null' => false,
            'default' => null,
        ));
    }

    /**
     * Old and new keys differ in length, so a rehashed row cannot clash
     * with one still waiting in the unique key.
     *
     * @return bool
     */
    public function afterUp()
    {
        $AttributeValue = ClassRegistry::init('AttributeValue');
        $AttributeValue->schema(true);
        $last = $AttributeValue->find('first', array(
            'fields' => array('AttributeValue.id'),
            'order' => array('AttributeValue.id' => 'DESC'),
        ));
        if (empty($last)) {
            return true;
        }
        $hash = $AttributeValue->getSqlDialect()->sha256Prefix(
            $AttributeValue->getDataSource()->name('value'),
            32
        );
        for ($from = 0; $from < (int)$last['AttributeValue']['id']; $from += self::CHUNK) {
            $AttributeValue->updateAll(array('AttributeValue.hash' => $hash), array(
                'AttributeValue.id >' => $from,
                'AttributeValue.id <=' => $from + self::CHUNK,
                'LENGTH(AttributeValue.hash)' => 16,
            ));
        }
        return true;
    }
}
