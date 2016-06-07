<?php
App::uses('AppModel', 'Model');
class OrgBlacklist extends AppModel{
	public $useTable = 'org_blacklists';
	public $recursive = -1;
	public $actsAs = array(
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'userModel' => 'User',
					'userKey' => 'user_id',
					'change' => 'full'),
			'Containable',
	);
	public $blacklistFields = array('org_uuid', 'comment', 'org_name');

	public $validate = array(
			'org_uuid' => array(
					'unique' => array(
							'rule' => 'isUnique',
							'message' => 'Organisation already blacklisted.'
					),
					'uuid' => array(
							'rule' => array('uuid'),
							'message' => 'Please provide a valid UUID'
					),
			)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		if (empty($this->data['OrgBlacklist']['id'])) $this->data['OrgBlacklist']['date_created'] = date('Y-m-d H:i:s');
		return true;
	}
}
