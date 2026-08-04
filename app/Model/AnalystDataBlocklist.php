<?php
App::uses('AppModel', 'Model');

class AnalystDataBlocklist extends AppModel
{
    public $useTable = 'analyst_data_blocklists';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ),
        'Containable',
    );

    public $blocklistFields = array('analyst_data_uuid', 'comment', 'analyst_data_info', 'analyst_data_orgc');
    public $blocklistTarget = 'analyst_data';

    public $validate = array(
        'analyst_data_uuid' => array(
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'Analyst Data already blocklisted.'
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
        if (empty($this->data['AnalystDataBlocklist']['id'])) {
            $this->data['AnalystDataBlocklist']['date_created'] = date('Y-m-d H:i:s');
        }
        if (empty($this->data['AnalystDataBlocklist']['comment'])) {
            $this->data['AnalystDataBlocklist']['comment'] = '';
        }
        return true;
    }

    /**
     * @param string $analystDataUUID
     * @return bool
     */
    public function checkIfBlocked($analystDataUUID)
    {
        return $this->hasAny([
            'analyst_data_uuid' => $analystDataUUID,
        ]);
    }
}
