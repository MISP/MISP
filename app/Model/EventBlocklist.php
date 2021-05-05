<?php
App::uses('AppModel', 'Model');

class EventBlocklist extends AppModel
{
    public $useTable = 'event_blocklists';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'userModel' => 'User',
                    'userKey' => 'user_id',
                    'change' => 'full'),
            'Containable',
    );

    public $blocklistFields = array('event_uuid', 'comment', 'event_info', 'event_orgc');

    public $blocklistTarget = 'event';

    public $validate = array(
            'event_uuid' => array(
                    'unique' => array(
                            'rule' => 'isUnique',
                            'message' => 'Event already blocklisted.'
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
        $schema = $this->schema();
        if (!isset($schema['event_info'])) {
            $this->updateDatabase('addEventBlocklistsContext');
        }
        if (empty($this->data['EventBlocklist']['id'])) {
            $this->data['EventBlocklist']['date_created'] = date('Y-m-d H:i:s');
        }
        if (empty($this->data['EventBlocklist']['comment'])) {
            $this->data['EventBlocklist']['comment'] = '';
        }
        return true;
    }

    /**
     * @param string $eventUuid
     * @return bool
     */
    public function isBlocked($eventUuid)
    {
        $result = $this->find('first', [
            'conditions' => ['event_uuid' => $eventUuid],
            'fields' => ['id']
        ]);
        return !empty($result);
    }
}
