<?php
App::uses('AppModel', 'Model');

class SightingBlocklist extends AppModel
{
    public $useTable = 'sighting_blocklists';

    public $recursive = -1;

    public $actsAs = [
        'AuditLog',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'userModel' => 'User',
                    'userKey' => 'user_id',
                    'change' => 'full'),
            'Containable',
    ];
    public $blocklistFields = ['org_uuid', 'comment', 'org_name'];

    public $blocklistTarget = 'org';

    private $blockedCache = [];

    public $validate = array(
        'org_uuid' => array(
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'Organisation already blocklisted.'
            ),
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ),
        )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['OrgBlocklist']['id'])) {
            $this->data['OrgBlocklist']['date_created'] = date('Y-m-d H:i:s');
        }
        return true;
    }

    public function afterDelete()
    {
        parent::afterDelete();
        if (!empty($this->data['OrgBlocklist']['org_uuid'])) {
            $this->cleanupBlockedCount($this->data['OrgBlocklist']['org_uuid']);
        }
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($result['OrgBlocklist']['org_uuid'])) {
                $results[$k]['OrgBlocklist']['blocked_data'] = $this->getBlockedData($result['OrgBlocklist']['org_uuid']);
            }
        }
        return $results;
    }

    /**
     * @param array $eventArray
     */
    public function removeBlockedEvents(array &$eventArray)
    {
        $blocklistHits = $this->find('column', array(
            'conditions' => array('OrgBlocklist.org_uuid' => array_unique(array_column($eventArray, 'orgc_uuid'))),
            'fields' => array('OrgBlocklist.org_uuid'),
        ));
        if (empty($blocklistHits)) {
            return;
        }
        $blocklistHits = array_flip($blocklistHits);
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

        $isBlocked = $this->hasAny(['OrgBlocklist.org_uuid' => $orgUuid]);
        $this->blockedCache[$orgIdOrUuid] = $isBlocked;
        return $isBlocked;
    }

    private function getUUIDFromID($orgID)
    {
        $this->Organisation = ClassRegistry::init('Organisation');
        $orgUuid = $this->Organisation->find('first', [
            'conditions' => ['Organisation.id' => $orgID],
            'fields' => ['Organisation.uuid'],
            'recursive' => -1,
        ]);
        if (empty($orgUuid)) {
            return false; // org not found by ID, so it is not blocked
        }
        $orgUuid = $orgUuid['Organisation']['uuid'];
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
            $pipe = $redis->multi(Redis::PIPELINE)
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
            $pipe = $redis->multi(Redis::PIPELINE)
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
