<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Collection members are looked up by their uuid in lowercase, and the column
 * compares case by case: a member stored with capitals was never found.
 */
class Migration_20261125_121841_lowercase_collection_element_uuids extends AbstractMigration
{
    public $description = 'Collection members are stored under their uuid in lowercase';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const BATCH = 1000;

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
     * One pass over the table in id order. A member whose collection already
     * holds the lowercase spelling is a duplicate and goes, without a removal
     * record: partners hold the same member under the other spelling.
     *
     * @return bool
     */
    public function afterUp()
    {
        $CollectionElement = ClassRegistry::init('CollectionElement');
        $lastId = 0;
        do {
            $rows = $CollectionElement->find('all', array(
                'recursive' => -1,
                'callbacks' => false,
                'fields' => array('CollectionElement.id', 'CollectionElement.collection_id', 'CollectionElement.element_uuid'),
                'conditions' => array(
                    'CollectionElement.id >' => $lastId,
                    'CollectionElement.element_uuid !=' => null,
                ),
                'order' => array('CollectionElement.id' => 'ASC'),
                'limit' => self::BATCH,
            ));
            if (empty($rows)) {
                break;
            }
            $batch = array();
            foreach ($rows as $row) {
                $batch[] = $row['CollectionElement'];
            }
            $lastId = (int)end($batch)['id'];
            $mixed = array_values(array_filter($batch, function ($row) {
                return $row['element_uuid'] !== strtolower($row['element_uuid']);
            }));
            if (empty($mixed)) {
                continue;
            }
            if (!$this->apply($CollectionElement, self::plan($mixed, $this->lowercaseHeld($CollectionElement, $mixed)))) {
                return false;
            }
        } while (count($rows) === self::BATCH);
        return true;
    }

    /**
     * One batch's plan, in one transaction.
     *
     * @param Model $CollectionElement
     * @param array $plan plan()'s
     * @return bool
     */
    private function apply($CollectionElement, array $plan)
    {
        $db = $CollectionElement->getDataSource();
        $db->begin();
        $drop = array();
        foreach ($plan as $id => $action) {
            if ($action === 'drop') {
                $drop[] = $id;
                continue;
            }
            $lowered = $CollectionElement->updateAll(
                array('CollectionElement.element_uuid' => $db->value($action, 'string')),
                array('CollectionElement.id' => $id)
            );
            if (!$lowered) {
                $db->rollback();
                return false;
            }
        }
        if (!empty($drop) && !$CollectionElement->deleteAll(array('CollectionElement.id' => $drop), false, false)) {
            $db->rollback();
            return false;
        }
        $db->commit();
        return true;
    }

    /**
     * What becomes of each row not stored in lowercase: its lowercase uuid,
     * or 'drop' when its collection holds that spelling already. A row
     * lowercased here counts as held for the rows after it.
     *
     * @param array $rows [{id, collection_id, element_uuid}], in id order
     * @param array $held "collection_id:uuid" => true, for the lowercase
     *   spellings stored
     * @return array id => lowercase uuid | 'drop'
     */
    public static function plan(array $rows, array $held)
    {
        $plan = array();
        foreach ($rows as $row) {
            $lower = strtolower($row['element_uuid']);
            if ($lower === $row['element_uuid']) {
                continue;
            }
            $key = (int)$row['collection_id'] . ':' . $lower;
            if (isset($held[$key])) {
                $plan[(int)$row['id']] = 'drop';
            } else {
                $plan[(int)$row['id']] = $lower;
                $held[$key] = true;
            }
        }
        return $plan;
    }

    /**
     * @param Model $CollectionElement
     * @param array $rows The batch's rows not stored in lowercase
     * @return array "collection_id:uuid" => true, for the lowercase spellings
     *   their collections hold
     */
    private function lowercaseHeld($CollectionElement, array $rows)
    {
        $uuids = array();
        $collections = array();
        foreach ($rows as $row) {
            $uuids[strtolower($row['element_uuid'])] = true;
            $collections[(int)$row['collection_id']] = true;
        }
        $found = $CollectionElement->find('all', array(
            'recursive' => -1,
            'callbacks' => false,
            'fields' => array('CollectionElement.collection_id', 'CollectionElement.element_uuid'),
            'conditions' => array(
                'CollectionElement.element_uuid' => array_map('strval', array_keys($uuids)),
                'CollectionElement.collection_id' => array_keys($collections),
            ),
        ));
        $held = array();
        foreach ($found as $row) {
            $uuid = $row['CollectionElement']['element_uuid'];
            // Where the column compares case-insensitively, a row finds itself
            if ($uuid === strtolower($uuid)) {
                $held[(int)$row['CollectionElement']['collection_id'] . ':' . $uuid] = true;
            }
        }
        return $held;
    }
}
