<?php

App::uses('AbstractMigration', 'Migration');
App::uses('Collation', 'Migration');

/**
 * Collections shared beyond their organisation reach partners when published
 */
class Migration_20261028_100344_collection_publish_state extends AbstractMigration
{
    public $description = 'Collections shared beyond their organisation reach partners when published';

    public $requiresLogout = false;

    /**
     * A collection's published state, when it was last published and how far
     * its analysis went (as on events); on each member, whether partners hold
     * it; and the published members taken out since the last publish.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('collections')
            ->addColumn('published', 'boolean', array(
                'null' => false,
                'default' => 0,
                'after' => 'distribution',
            ))
            ->addColumn('last_published', 'datetime', array(
                'null' => true,
                'default' => null,
                'after' => 'published',
            ))
            ->addColumn('analysis', 'tinyinteger', array(
                'null' => false,
                'default' => 0,
                'after' => 'type',
            ));
        $schema->table('collection_elements')
            ->addColumn('published', 'boolean', array(
                'null' => false,
                'default' => 0,
                'after' => 'created',
            ));
        $schema->createTable('collection_element_removals', array(
            'id' => array('type' => 'primary_key'),
            'collection_id' => array('type' => 'biginteger', 'null' => false),
            'element_type' => array(
                'type' => 'string', 'length' => 80, 'null' => false,
                'charset' => 'ascii', 'collate' => 'ascii_general_ci',
            ),
            'element_uuid' => array(
                'type' => 'string', 'length' => 40, 'null' => true, 'default' => null,
                'collate' => Collation::ASCII,
            ),
            'element_sha256' => array(
                'type' => 'string', 'length' => 64, 'null' => true, 'default' => null,
                'collate' => Collation::ASCII,
            ),
            'user_id' => array('type' => 'biginteger', 'null' => true, 'default' => null),
            'created' => array('type' => 'datetime', 'null' => false),
        ), array(
            'indexes' => array(
                'collection_id' => array(),
                'unique_element' => array('column' => array('element_uuid', 'collection_id'), 'unique' => true),
                'unique_element_sha256' => array('column' => array('element_sha256', 'collection_id'), 'unique' => true),
            ),
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
        ));
    }

    /**
     * Shared collections start published, members included, so nothing stops
     * reaching partners on the day of the upgrade. Organisation-only ones were
     * never sent anywhere and start unpublished.
     *
     * @return bool
     */
    public function afterUp()
    {
        $Collection = ClassRegistry::init('Collection');
        $Collection->schema(true);
        $Collection->CollectionElement->schema(true);
        $shared = $Collection->find('list', array(
            'recursive' => -1,
            'fields' => array('Collection.id', 'Collection.id'),
            'conditions' => array('Collection.distribution !=' => 0),
        ));
        if (empty($shared)) {
            return true;
        }
        $now = date('Y-m-d H:i:s');
        foreach (array_chunk(array_values($shared), 1000) as $ids) {
            $ids = array_map('intval', $ids);
            $done = $Collection->updateAll(
                array('Collection.published' => true, 'Collection.last_published' => "'" . $now . "'"),
                array('Collection.id' => $ids)
            );
            $done = $done && $Collection->CollectionElement->updateAll(
                array('CollectionElement.published' => true),
                array('CollectionElement.collection_id' => $ids)
            );
            if (!$done) {
                return false;
            }
        }
        return true;
    }
}
