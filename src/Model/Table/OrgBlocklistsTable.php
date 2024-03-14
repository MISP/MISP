<?php


namespace App\Model\Table;

use App\Lib\Tools\RedisTool;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Collection\CollectionInterface;
use Cake\Datasource\EntityInterface;
use Cake\Datasource\Exception\RecordNotFoundException;
use Cake\Event\EventInterface;
use Cake\ORM\Query;
use Cake\ORM\RulesChecker;
use Cake\Validation\Validator;

class OrgBlocklistsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
    }

    public $blocklistFields = ['org_uuid', 'comment', 'org_name'];

    public $blocklistTarget = 'org';

    private $blockedCache = [];

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence('org_uuid')
            ->notEmptyString('org_uuid')
            ->uuid('org_uuid');

        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['org_uuid']));
        return $rules;
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if (empty($entity->id)) {
            $entity->created = date('Y-m-d H:i:s');
        }
        return true;
    }

    public function afterDelete(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if (!empty($entity['org_uuid'])) {
            $this->cleanupBlockedCount($entity['org_uuid']);
        }
    }

    public function beforeFind(EventInterface $event, Query $query, ArrayObject $options)
    {
        $query->formatResults(
            function (CollectionInterface $results) {
                return $results->map(
                    function ($row) {
                        if (isset($row['org_uuid'])) {
                            $row['blocked_data'] = $this->getBlockedData($row['org_uuid']);
                        }
                        return $row;
                    }
                );
            },
            $query::APPEND
        );
    }

    /**
     * @param array $eventArray
     */
    public function removeBlockedEvents(array &$eventArray)
    {
        if (empty($eventArray)) {
            return;
        }

        // When event array contains a lot events, it is more efficient to fetch all blocked events
        $blocklistHits = $this->find(
            'column',
            [
                'conditions' => ['org_uuid IN' => array_column($eventArray, 'orgc_uuid')],
                'fields' => ['org_uuid'],
            ]
        );
        if (empty($blocklistHits)) {
            return;
        }
        $blocklistHits = array_flip($blocklistHits->toArray());
        foreach ($eventArray as $k => $event) {
            if (isset($blocklistHits[$event['orgc_uuid']])) {
                unset($eventArray[$k]);
            }
        }
    }

    /**
     * @param int|string $orgIdOrUuid Organisation ID or UUID
     * @return bool
     */
    public function isBlocked($orgIdOrUuid)
    {
        if (isset($this->blockedCache[$orgIdOrUuid])) {
            return $this->blockedCache[$orgIdOrUuid];
        }

        if (is_numeric($orgIdOrUuid)) {
            $orgUuid = $this->getUUIDFromID($orgIdOrUuid);
        } else {
            $orgUuid = $orgIdOrUuid;
        }

        $isBlocked = $this->exists(['org_uuid' => $orgUuid]);
        $this->blockedCache[$orgIdOrUuid] = $isBlocked;

        return $isBlocked;
    }

    private function getUUIDFromID($orgID)
    {
        $OrganisationsTable = $this->fetchTable('Organisations');
        try {
            $orgUuid = $OrganisationsTable->get(
                $orgID,
                [
                    'fields' => ['Organisations.uuid'],
                ]
            );
        } catch (RecordNotFoundException $e) {
            return false;
        }
        if (empty($orgUuid)) {
            return false; // org not found by ID, so it is not blocked
        }
        $orgUuid = $orgUuid['uuid'];

        return $orgUuid;
    }

    public function saveEventBlocked($orgIdOrUUID)
    {
        if (is_numeric($orgIdOrUUID)) {
            $orgcUUID = $this->getUUIDFromID($orgIdOrUUID);
        } else {
            $orgcUUID = $orgIdOrUUID;
        }
        $lastBlockTime = time();
        $redisKeyBlockAmount = "misp:blocklist_blocked_amount:{$orgcUUID}";
        $redisKeyBlockLastTime = "misp:blocklist_blocked_last_time:{$orgcUUID}";
        $redis = RedisTool::init();
        if ($redis !== false) {
            $pipe = $redis->multi(\Redis::PIPELINE)
                ->incr($redisKeyBlockAmount)
                ->set($redisKeyBlockLastTime, $lastBlockTime);
            $pipe->exec();
        }
    }

    private function cleanupBlockedCount($orgcUUID)
    {
        $redisKeyBlockAmount = "misp:blocklist_blocked_amount:{$orgcUUID}";
        $redisKeyBlockLastTime = "misp:blocklist_blocked_last_time:{$orgcUUID}";
        $redis = RedisTool::init();
        if ($redis !== false) {
            $pipe = $redis->multi(\Redis::PIPELINE)
                ->del($redisKeyBlockAmount)
                ->del($redisKeyBlockLastTime);
            $pipe->exec();
        }
    }

    public function getBlockedData($orgcUUID)
    {
        $redisKeyBlockAmount = "misp:blocklist_blocked_amount:{$orgcUUID}";
        $redisKeyBlockLastTime = "misp:blocklist_blocked_last_time:{$orgcUUID}";
        $blockData = [
            'blocked_amount' => false,
            'blocked_last_time' => false,
        ];
        $redis = RedisTool::init();
        if ($redis !== false) {
            $blockData['blocked_amount'] = $redis->get($redisKeyBlockAmount);
            $blockData['blocked_last_time'] = $redis->get($redisKeyBlockLastTime);
        }
        return $blockData;
    }
}
