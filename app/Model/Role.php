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
 * TODO ACL: 1: be requester to CakePHP ACL system
 *
 * @var unknown_type
 */
	public $actsAs = array('Acl' => array('type' => 'requester'), 'MagicTools.OrphansProtectable', 'Trim');

/**
 * TODO ACL: 2: hook Role into CakePHP ACL system (so link to aros)
 */
	public function parentNode() {
		return null;
	}

/**
 * Virtual field
 *
 * @var array
 */
	public $virtualFields = array(
		'permission' => "IF (Role.perm_add && Role.perm_modify && Role.perm_publish, '3', IF (Role.perm_add && Role.perm_modify_org, '2', IF (Role.perm_add, '1', '0')))",
	);

	public function massageData(&$data) {
		switch ($data['Role']['permission']) {
			case '0':
				$data['Role']['perm_add'] = false;
				$data['Role']['perm_modify'] = false;
				$data['Role']['perm_modify_org'] = false;
				$data['Role']['perm_publish'] = false;
				break;
			case '1':
				$data['Role']['perm_add'] = true;
				$data['Role']['perm_modify'] = true; // SHOULD BE true
				$data['Role']['perm_modify_org'] = false;
				$data['Role']['perm_publish'] = false;
				break;
			case '2':
				$data['Role']['perm_add'] = true;
				$data['Role']['perm_modify'] = true;
				$data['Role']['perm_modify_org'] = true;
				$data['Role']['perm_publish'] = false;
				break;
			case '3':
				$data['Role']['perm_add'] = true;
				$data['Role']['perm_modify'] = true; // ?
				$data['Role']['perm_modify_org'] = true; // ?
				$data['Role']['perm_publish'] = true;
				break;
		}
		return $data;
	}
}