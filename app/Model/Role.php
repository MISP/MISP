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
		'name' => array(
			'notempty' => array(
				'rule' => array('notempty'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
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