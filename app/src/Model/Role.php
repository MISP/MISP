<?php

namespace Model;

class Role extends AppModel {

	public $validate = array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
		),
	);

	public $hasMany = array(
		'User' => array(
			'className' => 'User',
			'foreignKey' => 'role_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		)
	);

	public $actsAs = array(
			'Trim',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Role',
					'roleKey' => 'role_id',
					'change' => 'full'
			),
	);

	public $virtualFields = array(
		'permission' => "CASE WHEN (Role.perm_add + Role.perm_modify + Role.perm_publish = 3) THEN '3' WHEN (Role.perm_add + Role.perm_modify_org = 2) THEN '2' WHEN (Role.perm_add = 1) THEN '1' ELSE '0' END",
	);

	public $permFlags = array(
		'perm_admin' => array('id' => 'RolePermAdmin', 'text' => 'Admin', 'readonlyenabled' => false),
		'perm_site_admin' => array('id' => 'RolePermSiteAdmin', 'text' => 'Site Admin', 'readonlyenabled' => false),
		'perm_sync' => array('id' => 'RolePermSync', 'text' => 'Sync Actions', 'readonlyenabled' => true),
		'perm_audit' => array('id' => 'RolePermAudit', 'text' => 'Audit Actions', 'readonlyenabled' => true),
		'perm_auth' => array('id' => 'RolePermAuth', 'text' => 'Auth key access', 'readonlyenabled' => true),
		'perm_regexp_access' => array('id' => 'RolePermRegexpAccess', 'text' => 'Regex Actions', 'readonlyenabled' => false),
		'perm_tagger' => array('id' => 'RolePermTagger', 'text' => 'Tagger', 'readonlyenabled' => false),
		'perm_tag_editor' => array('id' => 'RolePermTagEditor', 'text' => 'Tag Editor', 'readonlyenabled' => false),
		'perm_template' => array('id' => 'RolePermTemplate', 'text' => 'Template Editor', 'readonlyenabled' => false),
		'perm_sharing_group' => array('id' => 'RolePermSharingGroup', 'text' => 'Sharing Group Editor', 'readonlyenabled' => false),
		'perm_delegate' => array('id' => 'RolePermDelegate', 'text' => 'Delegations Access', 'readonlyenabled' => false),
		'perm_sighting' => array('id' => 'RolePermSighting', 'text' => 'Sighting Creator', 'readonlyenabled' => true)
	);

	public $premissionLevelName = array('Read Only', 'Manage Own Events', 'Manage Organisation Events', 'Manage and Publish Organisation Events');

	public function beforeSave($options = array()) {
	  //Conversion from the named data access permission levels
		switch ($this->data['Role']['permission']) {
			case '0':
				$this->data['Role']['perm_add'] = 0;
				$this->data['Role']['perm_modify'] = 0;
				$this->data['Role']['perm_modify_org'] = 0;
				$this->data['Role']['perm_publish'] = 0;
				break;
			case '1':
				$this->data['Role']['perm_add'] = 1;
				$this->data['Role']['perm_modify'] = 1;
				$this->data['Role']['perm_modify_org'] = 0;
				$this->data['Role']['perm_publish'] = 0;
				break;
			case '2':
				$this->data['Role']['perm_add'] = 1;
				$this->data['Role']['perm_modify'] = 1;
				$this->data['Role']['perm_modify_org'] = 1;
				$this->data['Role']['perm_publish'] = 0;
				break;
			case '3':
				$this->data['Role']['perm_add'] = 1;
				$this->data['Role']['perm_modify'] = 1;
				$this->data['Role']['perm_modify_org'] = 1;
				$this->data['Role']['perm_publish'] = 1;
				break;
			default:
				break;
		}
		return true;
	}
}
