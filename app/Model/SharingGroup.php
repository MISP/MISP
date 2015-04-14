<?php
App::uses('AppModel', 'Model');

class SharingGroup extends AppModel {
	
	public $actsAs = array('Containable');
	public $validate = array(
		'name' => array(
			'unique' => array(
				'rule' => 'isUnique',
				'message' => 'A sharing group with this name already exists.'
			),
			'notempty' => array(
				'rule' => array('notempty'),
			),
		),
		'uuid' => array(
			'uuid' => array(
				'rule' => array('uuid'),
				'message' => 'Please provide a valid UUID'
			),
		)
	);
	public $hasMany = array(
		'SharingGroupOrg' => array(
			'className' => 'SharingGroupOrg',
			'foreignKey' => 'sharing_group_id',
			'dependent' => true,	// cascade deletes
		),
		'SharingGroupServer' => array(
			'className' => 'SharingGroupServer',
			'foreignKey' => 'sharing_group_id',
			'dependent' => true,	// cascade deletes
		)
	);
	
	public $belongsTo = array(
		'Organisation' => array(
			'className' => 'Organisation',
			'foreignKey' => false,
			'conditions' => array('Organisation.uuid = SharingGroup.organisation_uuid'),
		)
	);


	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		if (empty($this->data['SharingGroup']['uuid'])) {
			$this->data['SharingGroup']['uuid'] = String::uuid();
		}
		$date = date('Y-m-d H:i:s');
		if (empty($this->data['SharingGroup']['date_created'])) {
			$this->data['SharingGroup']['date_created'] = $date;
		}
		$this->data['SharingGroup']['date_modified'] = $date;
		return true;
	}
	
	// returns a list of all sharing groups that the user is allowed to see
	// scope can be:
	// full: Entire SG object with all organisations and servers attached
	// name: array in ID => name key => value format
	// false: array with all IDs
	public function fetchAllAuthorised($user, $scope = false, $active = false) {
		$conditions = array();
		if ($active !== false) $conditions['AND'][] = array('SharingGroup.active' => $active);
		if ($user['Role']['perm_site_admin']) {
			$sgs = $this->find('all', array(
				'recursive' => -1,
				'fields' => array('id'),
				'conditions' => $conditions
			));
			$ids = array();
			foreach ($sgs as $sg) $ids[] = $sg['SharingGroup']['id'];
		} else {
			$ids = array_unique(array_merge($this->SharingGroupServer->fetchAllAuthorised(), $this->SharingGroupOrg->fetchAllAuthorised($user['Organisation']['id'])));
		}
		if ($scope === 'full') {
			if (!empty($ids)) $conditions['And'][] = array('SharingGroup.id' => $ids);
			$sgs = $this->find('all', array(
				'contain' => array('SharingGroupServer' => array('Server'), 'SharingGroupOrg' => array('Organisation'), 'Organisation'),
				'conditions' => $conditions,
				'order' => 'name ASC'
			));
			return $sgs;
		} else if ($scope == 'name') {
			if (!empty($ids)) $conditions['And'][] = array('SharingGroup.id' => $ids);
			$sgs = $this->find('list', array(
				'recursive' => -1,
				'fields' => array('id', 'name'),
				'order' => 'name ASC',
				'conditions' => $conditions,
			));
			return $sgs;
		} else {
			return $ids;
		}
	}
	
	// returns true if the SG exists and the user is allowed to see it
	public function checkIfAuthorised($user, $id) {
		if (!isset($user['id'])) throw new MethodNotAllowedException('Invalid user.');
		$this->id = $id;
		if (!$this->exists()) return false;
		if ($user['Role']['perm_site_admin'] || $this->SharingGroupServer->checkIfAuthorised($id) || $this->SharingGroupOrg->checkIfAuthorised($id, $user['Organisation']['id'])) return true;
		return false;
	}
	
	public function checkIfOwner($user, $id) {
		if (!isset($user['id'])) throw new MethodNotAllowedException('Invalid user.');
		$this->id = $id;
		if (!$this->exists()) return false;
		if ($user['Role']['perm_site_admin']) return true;
		$sg = $this->find('first', array(
				'conditions' => array('SharingGroup.id' => $id),
				'recursive' => -1,
				'fields' => array('id', 'organisation_uuid'),
		));
		return ($sg['SharingGroup']['organisation_uuid'] === $user['Organisation']['uuid']);
	}
}
