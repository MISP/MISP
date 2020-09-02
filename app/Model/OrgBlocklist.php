<?php
App::uses('AppModel', 'Model');
class OrgBlocklist extends AppModel
{
    public $useTable = 'org_blocklists';

    public $recursive = -1;

    public $actsAs = array(
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'userModel' => 'User',
                    'userKey' => 'user_id',
                    'change' => 'full'),
            'Containable',
    );
    public $blocklistFields = array('org_uuid', 'comment', 'org_name');

    public $blocklistTarget = 'org';

    public $validate = array(
            'org_uuid' => array(
                    'unique' => array(
                            'rule' => 'isUnique',
                            'message' => 'Organisation already blocklisted.'
                    ),
                    'uuid' => array(
                        'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                        'message' => 'Please provide a valid UUID'
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
}
