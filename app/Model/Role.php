<?php
App::uses('AppModel', 'Model');
/**
 * Role Model
 *
 * @property User $User
 */
class Role extends AppModel {

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
		),
	);

/**
 * hasMany associations
 *
 * @var array
 */
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

/**
 *
 * @var unknown_type
 */
	public $actsAs = array(
			'Trim',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Role',
					'roleKey' => 'role_id',
					'change' => 'full'
			),
	);


/**
 * Virtual field
 *
 * @var array
 */

	public $virtualFields = array(
		'permission' => "IF (Role.perm_add && Role.perm_modify && Role.perm_publish, '3', IF (Role.perm_add && Role.perm_modify_org, '2', IF (Role.perm_add, '1', '0')))",
	);

	public $permFlags = array(
		'perm_admin' => array('id' => 'RolePermAdmin', 'text' => 'Admin'),
		'perm_site_admin' => array('id' => 'RolePermSiteAdmin', 'text' => 'Site Admin'),
		'perm_sync' => array('id' => 'RolePermSync', 'text' => 'Sync Actions'),
		'perm_audit' => array('id' => 'RolePermAudit', 'text' => 'Audit Actions'),
		'perm_auth' => array('id' => 'RolePermAuth', 'text' => 'Auth key access'),
		'perm_regexp_access' => array('id' => 'RolePermRegexpAccess', 'text' => 'Regex Actions'),
		'perm_tagger' => array('id' => 'RolePermTagger', 'text' => 'Tagger'),
		'perm_tag_editor' => array('id' => 'RolePermTagEditor', 'text' => 'Tag Editor'),
		'perm_template' => array('id' => 'RolePermTemplate', 'text' => 'Template Editor'),
		'perm_sharing_group' => array('id' => 'RolePermSharingGroup', 'text' => 'Sharing Group Editor'),
	);

	public $premissionLevelName = array('Read Only', 'Manage Own Events', 'Manage Organisation Events', 'Manage and Publish Organisation Events');

	public function beforeSave($options = array()) {
		switch ($this->data['Role']['permission']) {
			case '0':
				$this->data['Role']['perm_add'] = false;
				$this->data['Role']['perm_modify'] = false;
				$this->data['Role']['perm_modify_org'] = false;
				$this->data['Role']['perm_publish'] = false;
				break;
			case '1':
				$this->data['Role']['perm_add'] = true;
				$this->data['Role']['perm_modify'] = true; // SHOULD BE true
				$this->data['Role']['perm_modify_org'] = false;
				$this->data['Role']['perm_publish'] = false;
				break;
			case '2':
				$this->data['Role']['perm_add'] = true;
				$this->data['Role']['perm_modify'] = true;
				$this->data['Role']['perm_modify_org'] = true;
				$this->data['Role']['perm_publish'] = false;
				break;
			case '3':
				$this->data['Role']['perm_add'] = true;
				$this->data['Role']['perm_modify'] = true; // ?
				$this->data['Role']['perm_modify_org'] = true; // ?
				$this->data['Role']['perm_publish'] = true;
				break;
			default:
				break;
		}
		return true;
	}
}
