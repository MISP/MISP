<?php
App::uses('AppModel', 'Model');
class SharingGroupServer extends AppModel {
	public $actsAs = array('Containable');
	public $validate = array(
			
	);
	
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
	

	public function updateServersForSG($id, $new_servers, $old_servers, $limitServers) {
		// Check first if we need to handle the servers at all, or if we should just delete all servers from the SG (depending on the checkbox in the "MISP instances" tab).
		if ($limitServers) {
			foreach ($new_servers as $server) {
				$SgS = array(
						'sharing_group_id' => $id,
						'server_id' => $server['id'],
						'all_orgs' => $server['all_orgs']
				);
		
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
				} else {
					if ($found['all_orgs'] == $SgS['all_orgs']) continue;
					$SgS['id'] = $found['id'];
				}
				$this->save($SgS);
					
			}
			// We are left with some "old orgs" that are not in the new list. This means that they can be safely deleted.
			foreach ($old_servers as $old_server) $this->SharingGroup->SharingGroupServer->delete($old_server['id']);
				
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
}
