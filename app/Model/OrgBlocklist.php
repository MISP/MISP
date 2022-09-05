<?php
App::uses('AppModel', 'Model');

class OrgBlocklist extends AppModel
{
    public $useTable = 'org_blocklists';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'userModel' => 'User',
                    'userKey' => 'user_id',
                    'change' => 'full'),
            'Containable',
    );
    public $blocklistFields = array('org_uuid', 'comment', 'org_name');

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
            $this->Organisation = ClassRegistry::init('Organisation');
            $orgUuid = $this->Organisation->find('first', [
                'conditions' => ['Organisation.id' => $orgIdOrUuid],
                'fields' => ['Organisation.uuid'],
                'recursive' => -1,
            ]);
            if (empty($orgUuid)) {
                return false; // org not found by ID, so it is not blocked
            }
            $orgUuid = $orgUuid['Organisation']['uuid'];
        } else {
            $orgUuid = $orgIdOrUuid;
        }

        $isBlocked = $this->hasAny(['OrgBlocklist.org_uuid' => $orgUuid]);
        $this->blockedCache[$orgIdOrUuid] = $isBlocked;
        return $isBlocked;
    }
}
