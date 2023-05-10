<?php


namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Validation\Validator;
use Cake\ORM\RulesChecker;
use Cake\Event\EventInterface;
use Cake\Datasource\EntityInterface;
use ArrayObject;

class EventBlocklistsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
    }

    public $blocklistFields = array('event_uuid', 'comment', 'event_info', 'event_orgc');

    public $blocklistTarget = 'event';

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence('event_uuid')
            ->notEmptyString('event_uuid')
            ->uuid('event_uuid');

        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['event_uuid']));
        return $rules;
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if (empty($entity->id)) {
            $entity->created = date('Y-m-d H:i:s');
        }
        if (empty($entity->comment)) {
            $entity->comment = '';
        }
        return true;
    }

    /**
     * @param array $eventArray
     */
    public function removeBlockedEvents(array &$eventArray)
    {
        // When event array contains a lot events, it is more efficient to fetch all blocked events
        $conditions = (count($eventArray) > 10000) ? [] : ['EventBlocklist.event_uuid' => array_column($eventArray, 'uuid')];
        $blocklistHits = $this->find('column', [
            'conditions' => $conditions,
            'fields' => ['EventBlocklist.event_uuid'],
        ]);
        if (empty($blocklistHits)) {
            return;
        }
        $blocklistHits = array_flip($blocklistHits);
        foreach ($eventArray as $k => $event) {
            if (isset($blocklistHits[$event['uuid']])) {
                unset($eventArray[$k]);
            }
        }
    }

    /**
     * @param string $eventUuid
     * @return bool
     */
    public function isBlocked($eventUuid)
    {
        return $this->hasAny(['event_uuid' => $eventUuid]);
    }
}
