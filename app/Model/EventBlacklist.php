<?php
App::uses('AppModel', 'Model');
class EventBlacklist extends AppModel
{
    public $useTable = 'event_blacklists';

    public $recursive = -1;

    public $actsAs = array(
            'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
                    'userModel' => 'User',
                    'userKey' => 'user_id',
                    'change' => 'full'),
            'Containable',
    );

    public $blacklistFields = array('event_uuid', 'comment', 'event_info', 'event_orgc');

    public $validate = array(
            'event_uuid' => array(
                    'unique' => array(
                            'rule' => 'isUnique',
                            'message' => 'Event already blacklisted.'
                    ),
                    'uuid' => array(
                            'rule' => array('uuid'),
                            'message' => 'Please provide a valid UUID'
                    ),
            )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $schema = $this->schema();
        if (!isset($schema['event_info'])) {
            $this->updateDatabase('addEventBlacklistsContext');
        }
        $date = date('Y-m-d H:i:s');
        if (empty($this->data['EventBlacklist']['id'])) {
            $this->data['EventBlacklist']['date_created'] = $date;
        }
        if (empty($this->data['EventBlacklist']['comment'])) {
            $this->data['EventBlacklist']['comment'] = '';
        }
        return true;
    }
}
