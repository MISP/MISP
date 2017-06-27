<?php
App::uses('AppModel', 'Model');

class SharingGroupServer extends AppModel {

	public $actsAs = array('Containable');

	public $belongsTo = array(
		'SharingGroup' => array(
			'className' => 'SharingGroup',
			'foreignKey' => 'sharing_group_id'
		),
		'Server' => array(
				'className' => 'Server',
				'foreignKey' => 'server_id',
				//'conditions' => array('SharingGroupElement.organisation_uuid' => 'Organisation.uuid')
		)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
	}


	public function updateServersForSG($id, $new_servers, $old_servers, $roaming, $user) {
		$log = ClassRegistry::init('Log');
		// Check first if we need to handle the servers at all, or if we should just delete all servers from the SG (depending on the checkbox in the "MISP instances" tab).
		if (!$roaming) {
			foreach ($new_servers as $server) {
				$SgS = array(
						'sharing_group_id' => $id,
						'server_id' => $server['id'],
						'all_orgs' => $server['all_orgs']
				);
				$server_name = 'server (' . $server['id'] . ')';
				if ($server['id'] == 0) $server_name = 'the local server';

				$found = false;
				// If there is a match between a new server and an old server, keep the server in $found and unset it in the old server array.
				foreach ($old_servers as $k => $old_server) {
					if ($old_server['server_id'] == $server['id']) {
						$found = $old_servers[$k];
						unset($old_servers[$k]);
						break;
					}
				}

				// If we have not found the server previously, create a new sharing group server object.
				// Otherwise, if we have found it check whether the extended field has been altered, if not just continue without saving
				if (!$found) {
					$this->create();
					$isChange = false;
				} else {
					if ($found['all_orgs'] == $SgS['all_orgs']) continue;
					$isChange = true;
					$SgS['id'] = $found['id'];
				}
				$this->save($SgS);
				if ($this->save($SgS)) {
					$log->create();
					if ($isChange) $log->createLogEntry($user, 'edit', 'SharingGroupServer', $this->id, 'Sharing group (' . $id . '): Modified access rights for users on ' . $server_name . '.', ($server['all_orgs'] ? 'All organisations on server ' . $server['id'] . ' are now part of the sharing group.' : 'Organisations on ' . $server_name . ' are now not part of the sharing group unless they are present in the list of organisations.'));
					else $log->createLogEntry($user, 'add', 'SharingGroupServer', $this->id, 'Sharing group (' . $id . '): Added server (' . $server['id'] . ').', ucfirst($server_name) . ' added to Sharing group.' . ($server['all_orgs'] ? ' Sharing group visible to all organisations on the server.' : ''));
				}
			}
			// We are left with some "old orgs" that are not in the new list. This means that they can be safely deleted.
			foreach ($old_servers as $old_server) {
				if ($this->SharingGroup->SharingGroupServer->delete($old_server['id'])) {
					$log->create();
					$log->createLogEntry($user, 'delete', 'SharingGroupServer', $old_server['id'], 'Sharing group (' . $id . '): Removed server(' . $old_server['server_id'] . ').', 'Server (' . $old_server['server_id'] . ') removed from Sharing group.');
				}
			}
		} else {
			$this->deleteAll(array('sharing_group_id' => $id), false);
		}
	}

	// returns all sharing group IDs that have the local server (server_id = 0) as a server object with all orgs turned to 1
	// This basically lists all SGs that allow everyone on the instance to see events tagged with it
	public function fetchAllAuthorised() {
		$sgs = $this->find('all', array(
				'conditions' => array('all_orgs' => 1, 'server_id' => 0),
				'recursive' => -1,
				'fields' => array('sharing_group_id'),
		));
		$ids = array();
		foreach ($sgs as $sg) $ids[] = $sg['SharingGroupServer']['sharing_group_id'];
		return $ids;
	}

	// pass a sharing group ID, returns true if it has an attached server object with "all_orgs" ticked
	public function checkIfAuthorised($id) {
		$sg = $this->find('first', array(
				'conditions' => array('sharing_group_id' => $id, 'all_orgs' => 1),
				'recursive' => -1,
				'fields' => array('id'),
		));
		if (!empty($sg)) return true;
		return false;
	}

	public function fetchAllSGsForServer($server_id) {
		$sgs = $this->find('all', array(
			'recursive' => -1,
			'conditions' => array('server_id' => $server_id)
		));
		if (empty($sgs)) return array();
		$sgids = array();
		foreach ($sgs as $temp) {
			$sgids[] = $temp[$this->alias]['id'];
		}
		return $sgids;
	}
}
