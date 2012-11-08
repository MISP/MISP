<?php
App::uses('AppModel', 'Model');
/**
 * Group Model
 *
 * @property User $User
 */
class Group extends AppModel {

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
			'foreignKey' => 'group_id',
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
	public $actsAs = array('Acl' => array('type' => 'requester'), 'MagicTools.OrphansProtectable');

/**
 * TODO ACL: 2: hook Group into CakePHP ACL system (so link to aros)
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
		'permission' => "IF (Group.perm_add && Group.perm_modify && Group.perm_publish, '3', IF (Group.perm_add && Group.perm_modify_org, '2', IF (Group.perm_add, '1', '0')))",
	);

	public function massageData(&$data) {
		switch ($data['Group']['permission']) {
			case '0':
				$data['Group']['perm_add'] = false;
				$data['Group']['perm_modify'] = false;
				$data['Group']['perm_modify_org'] = false;
				$data['Group']['perm_publish'] = false;
				break;
			case '1':
				$data['Group']['perm_add'] = true;
				$data['Group']['perm_modify'] = true; // SHOULD BE true
				$data['Group']['perm_modify_org'] = false;
				$data['Group']['perm_publish'] = false;
				break;
			case '2':
				$data['Group']['perm_add'] = true;
				$data['Group']['perm_modify'] = true;
				$data['Group']['perm_modify_org'] = true;
				$data['Group']['perm_publish'] = false;
				break;
			case '3':
				$data['Group']['perm_add'] = true;
				$data['Group']['perm_modify'] = true; // ?
				$data['Group']['perm_modify_org'] = true; // ?
				$data['Group']['perm_publish'] = true;
				break;
		}
		return $data;
	}
}