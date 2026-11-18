<?php

App::uses('AbstractMigration', 'Migration');
App::uses('Collation', 'Migration');

/**
 * Collections hold values and objects MISP does not hold
 */
class Migration_20261118_080050_collection_members_outside_misp extends AbstractMigration
{
    public $description = 'Collections hold values and objects MISP does not hold';

    public $requiresLogout = false;

    /**
     * A value member keeps its text, and a member taken from a module's
     * answer where it came from. A standalone object is its own record,
     * never edited: the same answer is one record everywhere.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('collection_elements')
            ->addColumn('element_value', 'text', array(
                'null' => true,
                'default' => null,
                'after' => 'element_sha256',
            ))
            ->addColumn('origin', 'text', array(
                'null' => true,
                'default' => null,
                'after' => 'description',
            ));
        $schema->createTable('standalone_objects', array(
            'id' => array('type' => 'primary_key'),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'module' => array('type' => 'string', 'length' => 128, 'null' => true, 'default' => null, 'collate' => Collation::ASCII),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false),
            'template_uuid' => array('type' => 'string', 'length' => 40, 'null' => true, 'default' => null, 'collate' => Collation::ASCII),
            'template_version' => array('type' => 'integer', 'null' => true, 'default' => null),
            'meta_category' => array('type' => 'string', 'length' => 255, 'null' => true, 'default' => null),
            'description' => array('type' => 'text', 'null' => true, 'default' => null),
            'comment' => array('type' => 'text', 'null' => true, 'default' => null),
            'attributes' => array('type' => 'longtext', 'null' => false),
            'created' => array('type' => 'datetime', 'null' => false),
        ), array(
            'indexes' => array(
                'uuid' => array('unique' => true),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
        ));
    }

    /**
     * Every value member so far joined through an attribute holding it, so
     * the value table gives its text. One whose value is gone stays empty.
     *
     * @return bool
     */
    public function afterUp()
    {
        $CollectionElement = ClassRegistry::init('CollectionElement');
        $CollectionElement->schema(true);
        $values = ClassRegistry::init('MispAttribute')->loadAttributeValue();
        $lastId = 0;
        do {
            $rows = $CollectionElement->find('list', array(
                'recursive' => -1,
                'fields' => array('CollectionElement.id', 'CollectionElement.element_sha256'),
                'conditions' => array(
                    'CollectionElement.id >' => $lastId,
                    'CollectionElement.element_sha256 !=' => null,
                    'CollectionElement.element_value' => null,
                ),
                'order' => array('CollectionElement.id' => 'ASC'),
                'limit' => 500,
            ));
            if (empty($rows)) {
                break;
            }
            $lastId = max(array_keys($rows));
            $ids = $values->findBySha256(array_values(array_unique(array_map('strtolower', $rows))));
            $texts = empty($ids) ? array() : $values->fetchValues(array_values($ids));
            foreach ($rows as $id => $hex) {
                $valueId = $ids[strtolower($hex)] ?? null;
                if ($valueId === null || !isset($texts[$valueId])) {
                    continue;
                }
                $CollectionElement->create();
                $saved = $CollectionElement->save(
                    array('CollectionElement' => array('id' => $id, 'element_value' => $texts[$valueId])),
                    array('validate' => false, 'callbacks' => false, 'fieldList' => array('element_value'))
                );
                if (!$saved) {
                    return false;
                }
            }
        } while (count($rows) === 500);
        return true;
    }
}
