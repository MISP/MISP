<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Clear the sharing group of collections not distributed to one: saves used
 * to keep it on distributions 0-3, and the index showed its name to everyone
 * who could see the collection. Saves now clear it.
 */
class Migration_20261115_134841_clear_stale_collection_sharing_groups extends AbstractMigration
{
    public $description = 'Clear the sharing group of collections not distributed to one';

    /**
     * Only collections are touched.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * No DDL.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }

    /**
     * A re-run finds nothing left to clear.
     *
     * @return bool
     */
    public function afterUp()
    {
        $Collection = ClassRegistry::init('Collection');
        $conditions = array(
            'Collection.distribution !=' => 4,
            'NOT' => array('Collection.sharing_group_id' => null),
        );
        $count = $Collection->find('count', array(
            'recursive' => -1,
            'conditions' => $conditions,
        ));
        if ($count === 0) {
            return true;
        }
        if (!$Collection->updateAll(array('Collection.sharing_group_id' => null), $conditions)) {
            return false;
        }
        ClassRegistry::init('Log')->createLogEntry(
            'SYSTEM',
            'update_database',
            'Server',
            0,
            __('Cleared the sharing group of %s collections not distributed to one.', $count)
        );
        return true;
    }
}
