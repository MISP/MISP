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
	
	public $distributionDescriptions = array(
			0 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting will only allow members of the listed organisation(s) on this server to see it."),
			1 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes your own organisation, organisations on this MISP server and organisations running MISP servers that synchronise with this server. Any other organisations connected to such linked servers will be restricted from seeing the event. Use this option if you are on the central hub of this community."), // former Community
			2 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes all organisations on this MISP server, all organisations on MISP servers synchronising with this server and the hosting organisations of servers that connect to those afore mentioned servers (so basically any server that is 2 hops away from this one). Any other organisations connected to linked servers that are 2 hops away from this will be restricted from seeing the event. Use this option if this server isn't the central MISP hub of the community but is connected to it."),
			3 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next."),
	);
	
	public $distributionLevelResult = array(
		
	);
	
	public $distributionLevels = array(
			0 => 'My organisation only', 1 => 'Selected organisations only', 2 => 'Members of this instance', 3 => 'Members of this and directly connected instances', 4 => 'Everyone'
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
	public function fetchAllAuthorised($user) {
		if ($user['Role']['perm_site_admin']) {
			$sgs = $this->find('all', array(
				'recursive' => -1,
				'fields' => array('id'),
			));
			$ids = array();
			foreach ($sgs as $sg) $ids[] = $sg['SharingGroup']['id'];
		} else {
			$ids = array_unique(array_merge($this->SharingGroupServer->fetchAllAuthorised(), $this->SharingGroupOrg->fetchAllAuthorised($user['Organisation']['id'])));
		}
		return $ids;
	}
	
	// returns true if the SG exists and the user is allowed to see it
	public function checkIfAuthorised($user, $id) {
		if (!isset($user['id'])) throw new MethodNotAllowedException('Invalid user.');
		$this->id = $id;
		if (!$this->exists()) return false;
		if ($user['Role']['perm_site_admin'] || $this->SharingGroupServer->checkIfAuthorised($id) || $this->SharingGroupOrg->checkIfAuthorised($id, $user['Organisation']['id'])) return true;
		return false;
	}
	
	// compare a user's organisation (by org ID) to the sharing group. If a qualifying sharing group element is found, immediately return true
	// Qualifying elements include:
	// 1. An element of type 0 with the user's organisation set as the organisation ID
	// 2. An element with a type hither than 0. This indicates that the sg also has the "this community only", "connected communities", or "All" special elements.
	public function checkUserAccessForSG($orgId, $sg) {
		if ($sg['SharingGroup']['distribution'] > 1) return true;
		foreach ($sg['SharingGroupOrg'] as $sgo) {
			if ($sgo['Organisation']['id'] == $orgId) return true;
		}
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
