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
		'SharingGroupElement' => array(
			'className' => 'SharingGroupElement',
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
	
	public function checkIfVisible($user, $id) {
	
	}
	
	// checks the access level of a user for a sharing group
	// returns an integer indicating the access level
	// 0 = none
	// 1 = read
	// 2 = extend
	// 3 = full
	public function checkAccess($user, $id) {
		if (!isset($user['id'])) throw new MethodNotAllowedException('Invalid user.');
		if ($user['Role']['perm_site_admin']) return 3;
		$this->contain(
			array(
				'SharingGroupElement' => array(
					'Organisation' => array('id', 'uuid'),
				)
			)
		);
		$sg = $this->read(array('id', 'name', 'uuid', 'distribution', 'organisation_uuid', 'extendable'), $id);
		if ($sg['SharingGroup']['organisation_uuid'] == $user['Organisation']['uuid']) return 3;
		$inList = false;
		if ($sg['SharingGroup']['distribution'] > 1) $inList = true;
		else {
			foreach ($sg['SharingGroupElement'] as $sge) {
				if ($user['Organisation']['uuid'] == $sge['Organisation']['uuid']) $inList = true;
			}
		}
		if ($inList) {
			if ($sg['SharingGroup']['extendable']) return 2;
			else return 1;
		}
		return 0;
	}
	
	// Retrieve the Sharing Group objects that the user can see
	// Each sharing group contains the following:
	// 1 Organisation object (the creator)
	// * Sharing Group Elements, each with 0 or 1 Organisation object (0 for special elements, such as this community only)
	public function fetchSharingGroups($user, $isSiteAdmin, $idsOnly = false) {
		$ids = array();
		if (!isset($user)) throw new MethodNotAllowedException('Internal error (no user organisation specified).');
		$query = array(
			'contain' => array(
					'SharingGroupElement' => array(
						'Organisation' => array(	
					),
				)
			)
		);
		if ($idsOnly) {
			$query['fields'] = array('id', 'distribution');
			$query['contain']['SharingGroupElement']['fields'] = array('SharingGroupElement.id', 'SharingGroupElement.sharing_group_id', 'SharingGroupElement.organisation_id');
			$query['contain']['SharingGroupElement']['Organisation']['fields'] = array('Organisation.id');
		}
		$sharingGroups = $this->find('all', $query);
		foreach ($sharingGroups as $k => $sg) {
			if (!$isSiteAdmin && !$this->checkAccess($user, $sg['SharingGroup']['id'])) unset($sharingGroups[$k]);
			else $ids[] = $sg['SharingGroup']['id'];
		}
		if ($idsOnly) {
			return $ids;
		} else {
			return $sharingGroups;
		}
	}
	
	// compare a user's organisation (by org ID) to the sharing group. If a qualifying sharing group element is found, immediately return true
	// Qualifying elements include:
	// 1. An element of type 0 with the user's organisation set as the organisation ID
	// 2. An element with a type hither than 0. This indicates that the sg also has the "this community only", "connected communities", or "All" special elements.
	public function checkUserAccessForSG($orgId, $sg) {
		if ($sg['SharingGroup']['distribution'] > 1) return true;
		foreach ($sg['SharingGroupElement'] as $sge) {
			if ($sge['Organisation']['id'] == $orgId) return true;
		}
		return false;
	}
}
