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
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
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
			$this->data['SharingGroup']['uuid'] = $this->generateUuid();
		}
		$date = date('Y-m-d H:i:s');
		if (empty($this->data['SharingGroup']['date_created'])) {
			$this->data['SharingGroup']['date_created'] = $date;
		}
		$this->data['SharingGroup']['date_modified'] = $date;

		$sameNameSG = $this->find('first', array(
			'conditions' => array('SharingGroup.name' => $this->data['SharingGroup']['name']),
			'recursive' => -1,
			'fields' => array('SharingGroup.name')
		));
		if (!empty($sameNameSG) && !isset($this->data['SharingGroup']['id'])) {
			$this->data['SharingGroup']['name'] = $this->data['SharingGroup']['name'] . '_' . rand(0, 9999);
		}
		return true;
	}

	public function beforeDelete($cascade = false) {
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

	public function fetchAllAuthorisedForServer($server) {
		$conditions = array();
		$ids = array();
		$sgs = $this->SharingGroupOrg->fetchAllAuthorised($server['RemoteOrg']['id']);
		$sgs = array_merge($sgs, $this->SharingGroupServer->fetchAllSGsForServer($server['Server']['id']));
		return $sgs;
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
		if (!empty($ids)) $conditions['And'][] = array('SharingGroup.id' => $ids);
		else return array();
		if ($scope === 'full') {
			$sgs = $this->find('all', array(
				'contain' => array('SharingGroupServer' => array('Server'), 'SharingGroupOrg' => array('Organisation'), 'Organisation'),
				'conditions' => $conditions,
				'order' => 'name ASC'
			));
			return $sgs;
		} else if ($scope == 'name') {
			$sgs = $this->find('list', array(
				'recursive' => -1,
				'fields' => array('id', 'name'),
				'order' => 'name ASC',
				'conditions' => $conditions,
			));
			return $sgs;
		} else if ($scope == 'uuid') {
			$sgs = $this->find('list', array(
					'recursive' => -1,
					'fields' => array('id', 'uuid'),
					'conditions' => $conditions,
			));
			return $sgs;
		} else {
			return $ids;
		}
	}

	// Who can create a new sharing group with the elements pre-defined (via REST for example)?
	// 1. site admins
	// 2. Sharing group enabled users
	//    a. as long as they are creator or extender of the SG object
	// 3. Sync users
	//    a. as long as they are at least users of the SG (they can circumvent the extend rule to
	//       avoid situations where no one can create / edit an SG on an instance after a push)

	public function checkIfAuthorisedToSave($user, $sg) {
		if (isset($sg[0])) $sg = $sg[0];
		if ($user['Role']['perm_site_admin']) return true;
		if (!$user['Role']['perm_sharing_group']) return false;
		// First let us find out if we already have the SG
		$local = $this->find('first', array(
				'recursive' => -1,
				'conditions' => array('uuid' => $sg['uuid'])
		));
		if (empty($local)) {
			$found = false;
			$orgCheck = false;
			$serverCheck = false;
			if (isset($sg['SharingGroupOrg'])) {
				foreach ($sg['SharingGroupOrg'] as $org) {
					if (isset($org['Organisation'][0])) $org['Organisation'] = $org['Organisation'][0];
					if ($org['Organisation']['uuid'] == $user['Organisation']['uuid']) {
						if ($user['Role']['perm_sync'] || $org['extend'] == 1) $orgCheck = true;
					}
				}
			}
			if (isset($sg['SharingGroupServer'])) {
				foreach ($sg['SharingGroupServer'] as $server) {
					if (isset($server['Server'][0])) $server['Server'] = $server['Server'][0];
					if ($server['Server']['url'] == Configure::read('MISP.baseurl')) {
						$serverCheck = true;
						if ($user['Role']['perm_sync'] && $server['all_orgs']) $orgCheck = true;
					}
				}
			} else $serverCheck = true;
			if ($serverCheck && $orgCheck) return true;
		} else {
			return $this->checkIfAuthorisedExtend($user, $local['SharingGroup']['id']);
		}
		return false;
	}

	// Who is authorised to extend a sharing group?
	// 1. Site admins
	// 2. Sharing group permission enabled users that:
	//    a. Belong to the organisation that created the SG
	//    b. Have an organisation entry in the SG with the extend flag set
	// 3. Sync users that have synced the SG to the local instance
	public function checkIfAuthorisedExtend($user, $id) {
		if ($user['Role']['perm_site_admin']) return true;
		if (!$user['Role']['perm_sharing_group']) return false;
		if ($this->checkIfOwner($user, $id)) return true;
		$this->id = $id;
		if (!$this->exists()) return false;
		if ($user['Role']['perm_sync']) {
			$sg = $this->find('first', array(
				'conditions' => array(
					'id' => $id,
					'sync_user_id' => $user['id'],
				),
				'recursive' => -1,
			));
			if (empty($sg)) return false;
			else return true;
		}
		$sgo = $this->SharingGroupOrg->find('first', array(
				'conditions' => array(
						'sharing_group_id' => $id,
						'org_id' => $user['org_id'],
						'extend' => 1,
				),
				'recursive' => -1,
				'fields' => array('id', 'org_id', 'extend')
		));
		if (empty($sgo)) return false;
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
		if (empty($sg)) return array();
		// if the current server is marked as "all orgs" in the sharing group, just return true
		foreach ($sg['SharingGroupServer'] as $sgs) {
			if ($sgs['server_id'] == 0) {
				if ($sgs['all_orgs']) return true;
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
		foreach ($sg['SharingGroupOrg'] as $org) if (isset($org['Organisation']) && $org['Organisation']['uuid'] === $server['RemoteOrg']['uuid']) return true;
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
		$existingSG = !isset($sg['uuid']) ? null : $this->find('first', array(
				'recursive' => -1,
				'conditions' => array('SharingGroup.uuid' => $sg['uuid']),
				'contain' => array(
					'Organisation',
					'SharingGroupServer' => array('Server'),
					'SharingGroupOrg' => array('Organisation')
				)
		));
		$force = false;
		if (empty($existingSG)) {
			if (!$user['Role']['perm_sharing_group']) throw new Exception('User not authorised to create sharing groups.');
			$this->create();
			$newSG = array();
			$attributes = array('name', 'releasability', 'description', 'uuid', 'organisation_uuid', 'created', 'modified');
			foreach ($attributes as $a)	$newSG[$a] = isset($sg[$a]) ? $sg[$a] : null;
			$newSG['local'] = 0;
			$newSG['sync_user_id'] = $user['id'];
			if (!isset($sg['Organisation'])) {
				if (!isset($sg['SharingGroupOrg'])) return false;
				foreach ($sg['SharingGroupOrg'] as $k => $org) {
					if (isset($org['Organisation'][0])) $org['Organisation'] = $org['Organisation'][0];
					if ($org['Organisation']['uuid'] == $sg['organisation_uuid']) $newSG['org_id'] = $this->Organisation->captureOrg($org['Organisation'], $user);
				}
			} else {
				$newSG['org_id'] = $this->Organisation->captureOrg($sg['Organisation'], $user);
			}
			if (!$this->save($newSG)) return false;
			$sgids = $this->id;
		} else {
			if (!$this->checkIfAuthorised($user, $existingSG['SharingGroup']['id'])) throw new Exception('User not authorised to modify sharing groups.');
			if ($sg['modified'] > $existingSG['SharingGroup']['modified']) {
				if ($user['Role']['perm_sync'] && $existingSG['SharingGroup']['local'] == 0) $force = true;
				if ($force) {
					$sgids = $existingSG['SharingGroup']['id'];
					$editedSG = $existingSG['SharingGroup'];
					$attributes = array('name', 'releasability', 'description', 'created', 'modified');
					$different = false;
					foreach ($attributes as &$a) {
						if (!in_array($a, array('created', 'modified')) && $editedSG[$a] !== $sg[$a]) {
							$different = true;
						}
						$editedSG[$a] = $sg[$a];
					}
					$this->save($editedSG);
				} else {
					return $existingSG['SharingGroup']['id'];
				}
			} else {

				return $existingSG['SharingGroup']['id'];
			}
		}
		unset($sg['Organisation']);

		if (isset($sg['SharingGroupOrg']['id'])) {
			$temp = $sg['SharingGroupOrg'];
			unset($sg['SharingGroupOrg']);
			$sg['SharingGroupOrg'][0] = $temp;
		}
		foreach ($sg['SharingGroupOrg'] as $k => $org) {
			if (isset($org['Organisation'][0])) $org['Organisation'] = $org['Organisation'][0];
			$sg['SharingGroupOrg'][$k]['org_id'] = $this->Organisation->captureOrg($org['Organisation'], $user, $force);
			unset($sg['SharingGroupOrg'][$k]['Organisation']);
			if ($force) {
				// we are editing not creating here
				$temp = $this->SharingGroupOrg->find('first', array(
					'recursive' => -1,
					'conditions' => array(
						'sharing_group_id' => $existingSG['SharingGroup']['id'],
						'org_id' => $sg['SharingGroupOrg'][$k]['org_id']
					),
				));
				if (empty($temp)) {
					$this->SharingGroupOrg->create();
					$this->SharingGroupOrg->save(array('sharing_group_id' => $sgids, 'org_id' => $sg['SharingGroupOrg'][$k]['org_id'], 'extend' => $org['extend']));
				} else {
					if ($temp['SharingGroupOrg']['extend'] != $sg['SharingGroupOrg'][$k]['extend']) {
						$temp['SharingGroupOrg']['extend'] = $sg['SharingGroupOrg'][$k]['extend'];
						$this->SharingGroupOrg->save($temp['SharingGroupOrg']);
					}
				}
			} else {
				$this->SharingGroupOrg->create();
				$this->SharingGroupOrg->save(array('sharing_group_id' => $sgids, 'org_id' => $sg['SharingGroupOrg'][$k]['org_id'], 'extend' => $org['extend']));
			}
		}

		if (isset($sg['SharingGroupServer']['id'])) {
			$temp = $sg['SharingGroupServer'];
			unset($sg['SharingGroupServer']);
			$sg['SharingGroupServer'][0] = $temp;
		}
		foreach ($sg['SharingGroupServer'] as $k => $server) {
			if (isset($server[0])) $server = $server[0];
			$sg['SharingGroupServer'][$k]['server_id'] = $this->SharingGroupServer->Server->captureServer($server['Server'], $user, $force);
			if ($sg['SharingGroupServer'][$k]['server_id'] === false) unset($sg['SharingGroupServer'][$k]);
			else {
				if ($force) {
					// we are editing not creating here
					$temp = $this->SharingGroupServer->find('first', array(
						'recursive' => -1,
						'conditions' => array(
							'sharing_group_id' => $existingSG['SharingGroup']['id'],
							'server_id' => $sg['SharingGroupServer'][$k]['server_id']
						),
					));
					if ($temp['SharingGroupServer']['all_orgs'] != $sg['SharingGroupServer'][$k]['all_orgs']) {
						$temp['SharingGroupServer']['all_orgs'] = $sg['SharingGroupServer'][$k]['all_orgs'];
						$this->SharingGroupServer->save($temp['SharingGroupServer']);
					}
				} else {
					$this->SharingGroupServer->create();
					$this->SharingGroupServer->save(array('sharing_group_id' => $sgids, 'server_id' => $sg['SharingGroupServer'][$k]['server_id'], 'all_orgs' => $server['all_orgs']));
				}
			}
		}
		if (!empty($existingSG)) return $existingSG[$this->alias]['id'];
		return $this->id;
	}
}
