<?php
App::uses('AppModel', 'Model');

class SharingGroup extends AppModel {
	
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'SharingGroup',
					'roleKey' => 'sharing_group_id',
					'change' => 'full'
			),
	);
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
		),
		'Event',
		'Attribute',
		'Thread'
	);
	
	public $belongsTo = array(
		'Organisation' => array(
			'className' => 'Organisation',
			'foreignKey' => 'org_id',
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
	
	public function beforeDelete($cascade = false){
		$countEvent = $this->Event->find('count', array(
				'recursive' => -1,
				'conditions' => array('sharing_group_id' => $this->id)
		));
		$countThread = $this->Thread->find('count', array(
				'recursive' => -1,
				'conditions' => array('sharing_group_id' => $this->id)
		));
		$countAttribute = $this->Attribute->find('count', array(
				'recursive' => -1,
				'conditions' => array('sharing_group_id' => $this->id)
		));
		if (($countEvent + $countThread + $countAttribute) == 0) return true;
		return false;
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
	
	public function checkIfAuthorisedExtend($user, $id) {
		if ($this->checkIfOwner($user, $id)) return true;
		$this->id = $id;
		if (!$this->exists()) return false;
		$sg = $this->SharingGroupOrg->find('first', array(
			'conditions' => array(
				'sharing_group_id' => $id,
				'org_id' => $user['org_id'],
				'extend' => 1,
			),
			'recursive' => -1,
			'fields' => array('id', 'org_id', 'extend')
		));
		if (empty($sg)) return false;
		else return true;
	}
	
	// returns true if the SG exists and the user is allowed to see it
	public function checkIfAuthorised($user, $id) {
		if (!isset($user['id'])) throw new MethodNotAllowedException('Invalid user.');
		$this->id = $id;
		if (!$this->exists()) return false;
		if ($user['Role']['perm_site_admin'] || $this->SharingGroupServer->checkIfAuthorised($id) || $this->SharingGroupOrg->checkIfAuthorised($id, $user['org_id'])) return true;
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
				'fields' => array('id', 'org_id'),
		));
		return ($sg['SharingGroup']['org_id'] == $user['org_id']);
	}
	
	// Get all organisation ids that can see a SG
	public function getOrgsWithAccess($id) {
		$sg = $this->find('first', array(
			'conditions' => array('SharingGroup.id' => $id),
			'recursive' => -1,
			'fields' => array('id', 'org_id'),
			'contain' => array(
				'SharingGroupOrg' => array('fields' => array('id', 'org_id')),
				'SharingGroupServer' => array('fields' => array('id', 'server_id', 'all_orgs')),
			)
		));
		
		// if the current server is marked as "all orgs" in the sharing group, just return true
		foreach ($sg['SharingGroupServer'] as $sgs) {
			if ($sgs['server_id'] == 0) {
				if ('all_orgs') return true;
			}
		}
		
		// return a list of arrays with all organisations tied to the SG.
		$orgs = array();
		foreach ($sg['SharingGroupOrg'] as $sgo) {
			$orgs[] = $sgo['org_id'];
		}
		return $orgs;
	}
	
	public function checkIfServerInSG($sg, $server) {
		$results = array(
				'rule' => false,
				'orgs' => array(),
		);
		if (isset($sg['SharingGroupServer']) && !empty($sg['SharingGroupServer'])) {
			foreach ($sg['SharingGroupServer'] as $s) {
				if ($s['server_id'] == $server['Server']['id']) {
					if ($s['all_orgs']) return true;
					else $results['rule'] = 'conditional';
				}
			}
			if ($results['rule'] === false) return false;
		}
		foreach ($sg['SharingGroupOrg'] as $org) if ($org['Organisation']['uuid'] == $server['RemoteOrg']['uuid']) return true;
		return false;
	}
	
	public function getSGSyncRules($sg) {
		$results = array(
			'conditional' => array(),
			'full' => array(),
			'orgs' => array(),
			'no_server_settings' => false
		);
		if (isset($sg['SharingGroupServer'])) {
			foreach ($sg['SharingGroupServer'] as $server) {
				if ($server['server_id'] != 0) {
					if ($server['all_orgs']) $results['full'][] = $server['id'];
					else $results['conditional'][] = $server['id'];
				}
			}
			if (empty($results['full']) && empty($results['conditional'])) return false;
		} else {
			$results['no_server_settings'] = true;
		}
		foreach ($sg['SharingGroupOrg'] as $org) {
			$results['orgs'][] = $org['Organisation']['uuid'];
		}
		return $results;
	}
	
	public function captureSG($sg, $user) {
		$existingSG = $this->find('first', array(
				'recursive' => -1,
				'conditions' => array('SharingGroup.uuid' => $sg['uuid']),
				'contain' => array(
					'Organisation',
					'SharingGroupServer' => array('Server'),
					'SharingGroupOrg' => array('Organisation')
				)				
		));
		if (empty($existingSG)) {
			$this->create();
			$newSG = array();
			$attributes = array('name', 'releasability', 'description', 'uuid', 'organisation_uuid', 'created', 'modified');
			foreach ($attributes as $a)	$newSG[$a] = $sg[$a];
			$newSG['local'] = 0;
			$this->save($newSG);
		}
		
		$sg['org_id'] = $this->Organisation->captureOrg($sg['Organisation'], $user);
		unset ($sg['Organisation']);
		
		if (isset($sg['SharingGroupOrg']['id'])) {
			$temp = $sg['SharingGroupOrg'];
			unset($sg['SharingGroupOrg']);
			$sg['SharingGroupOrg'][0] = $temp;
		}
		foreach ($sg['SharingGroupOrg'] as $k => $org) {
			$sg['SharingGroupOrg'][$k]['org_id'] = $this->Organisation->captureOrg($org['Organisation'], $user);
			unset ($sg['SharingGroupOrg'][$k]['Organisation']);
		}
		
		if (isset($sg['SharingGroupServer']['id'])) {
			$temp = $sg['SharingGroupServer'];
			unset($sg['SharingGroupServer']);
			$sg['SharingGroupServer'][0] = $temp;
		}
		foreach ($sg['SharingGroupServer'] as $k => $server) {
			$sg['SharingGroupServer'][$k]['server_id'] = $this->SharingGroupServer->Server->captureServer($server['Server'], $user);
			if ($sg['SharingGroupServer'][$k]['server_id'] === false) unset ($sg['SharingGroupServer'][$k]);
			else unset ($sg['SharingGroupServer'][$k]['Server']);
		}
		if (!empty($existingSG)) return $existingSG[$this->alias]['id'];
		return $this->id;
	}
}
