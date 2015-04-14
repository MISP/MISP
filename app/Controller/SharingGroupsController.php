<?php
App::uses('AppController', 'Controller');

class SharingGroupsController extends AppController {
	public $components = array('Session', 'RequestHandler');
	
	public function beforeFilter() {
		parent::beforeFilter();
		if(!empty($this->request->params['admin']) && !$this->_isSiteAdmin()) $this->redirect('/');
		$sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user());
		$this->paginate = Set::merge($this->paginate,array('conditions' => array('SharingGroup.id' => $sgs)));
	}
	
	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'SharingGroup.name' => 'ASC'
			),
			'contain' => array('SharingGroupOrg' => array('Organisation'), 'Organisation', 'SharingGroupServer' => array('Server')),
	);
	
	public function add() {
		// add check for perm_sharing_group
		if($this->request->is('post')) {
			$json = json_decode($this->request->data['SharingGroup']['json'], true);
			$this->SharingGroup->create();
			$sg = $json['sharingGroup'];
			$sg['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
			$this->request->data['SharingGroup']['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
			if ($this->SharingGroup->save(array('SharingGroup' => $sg))) {
				foreach ($json['organisations'] as $org) {
					$this->SharingGroup->SharingGroupOrg->create();
					$this->SharingGroup->SharingGroupOrg->save(array(
							'sharing_group_id' => $this->SharingGroup->id,
							'org_id' => $org['id'],
							'extend' => $org['extend']
					));
				}
				foreach ($json['servers'] as $server) {
					$this->SharingGroup->SharingGroupServer->create();
					$this->SharingGroup->SharingGroupServer->save(array(
							'sharing_group_id' => $this->SharingGroup->id,
							'server_id' => $server['id'],
							'all_orgs' => $server['all_orgs']
					));
				}
				$this->redirect('/SharingGroups/view/' . $this->SharingGroup->id);
			} else {
				$validationReplacements = array(
					'notempty' => 'This field cannot be left empty.',
				);
				$validationErrors = $this->SharingGroup->validationErrors;
				$failedField = array_keys($validationErrors)[0];
				$reason = reset($this->SharingGroup->validationErrors)[0];
				foreach ($validationReplacements as $k => $vR) if ($reason == $k) $reason = $vR;
				$this->Session->setFlash('The sharing group could not be added. ' . ucfirst($failedField) . ': ' . $reason);
			}
		}
		$orgs = $this->SharingGroup->Organisation->find('all', array(
			'conditions' => array('local' => 1),
			'recursive' => -1,
			'fields' => array('id', 'name')
		));
		$this->set('orgs', $orgs);
		$this->set('localInstance', Configure::read('MISP.baseurl'));
		// We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
		$this->set('user', $this->Auth->user());
	}
	
	public function edit($id) {
		// add check for perm_sharing_group
		$this->SharingGroup->id = $id;
		if (!$this->SharingGroup->exists()) throw new NotFoundException('Invalid sharing group.');
		// check if the user is eligible to edit the SG (original creator or extend)
		$sharingGroup = $this->SharingGroup->find('first', array(
			'conditions' => array('SharingGroup.id' => $id),
			'recursive' => -1,
			'contain' => array(
					'SharingGroupOrg' => array(
						'Organisation' => array('name', 'local', 'id')
					), 
					'SharingGroupServer' => array(
						'Server' => array(
							'fields' => array('name', 'url', 'id')
						)
					), 
					'Organisation' => array(
						'fields' => array('name', 'local', 'id')	
					),
			),
		));
		if($this->request->is('post')) {
			$json = json_decode($this->request->data['SharingGroup']['json'], true);
			$sg = $json['sharingGroup'];
			$sg['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
			$this->request->data['SharingGroup']['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
			if ($this->SharingGroup->save(array('SharingGroup' => $sg))) {
				$this->SharingGroup->SharingGroupOrg->updateOrgsForSG($id, $json['organisations'], $sharingGroup['SharingGroupOrg']);
				$this->SharingGroup->SharingGroupServer->updateServersForSG($id, $json['servers'], $sharingGroup['SharingGroupServer'], $json['sharingGroup']['limitServers']);
				$this->redirect('/SharingGroups/view/' . $id);
			} else {
				$validationReplacements = array(
					'notempty' => 'This field cannot be left empty.',
				);
				$validationErrors = $this->SharingGroup->validationErrors;
				$failedField = array_keys($validationErrors)[0];
				$reason = reset($this->SharingGroup->validationErrors)[0];
				foreach ($validationReplacements as $k => $vR) if ($reason == $k) $reason = $vR;
				$this->Session->setFlash('The sharing group could not be added. ' . ucfirst($failedField) . ': ' . $reason);
			}
		}
		$orgs = $this->SharingGroup->Organisation->find('all', array(
			'conditions' => array('local' => 1),
			'recursive' => -1,
			'fields' => array('id', 'name')
		));
		$this->set('sharingGroup', $sharingGroup);
		$this->set('orgs', $orgs);
		$this->set('localInstance', Configure::read('MISP.baseurl'));
		// We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
		$this->set('user', $this->Auth->user());
	}
	
	public function delete($id) {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('Action not allowed, post request expected.');
		if (!$this->SharingGroup->checkIfOwner($this->Auth->user(), $id)) throw new MethodNotAllowedException('Action not allowed.');
		$this->SharingGroup->delete($id);
		$this->redirect('/SharingGroups/index');
	}
	
	public function index() {
		$ids = $this->SharingGroup->fetchAllAuthorised($this->Auth->user());
		$result = $this->paginate();
		// check if the current user can modify or delete the SG
		foreach ($result as $k => $sg) {
			//$result[$k]['access'] = $this->SharingGroup->checkAccess($this->Auth->user(), $sg['SharingGroup']['id']);
			if ($sg['SharingGroup']['organisation_uuid'] == $this->Auth->user('Organisation')['uuid']) {
				$result[$k]['editable'] = true;
			} else {
				$result[$k]['editable'] = false;
			}
		}
		$this->set('sharingGroups', $result);
	}
	
	public function view($id) {
		$sharingGroupIDs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user());
		if (!in_array($id, $sharingGroupIDs)) throw new MethodNotAllowedException('Sharing group doesn\'t exist or you do not have permission to access it.');
		$this->SharingGroup->id = $id;
		$this->SharingGroup->contain(array('SharingGroupOrg' => array('Organisation'), 'Organisation'));
		$this->SharingGroup->read();
		debug($this->SharingGroup->data);
		$this->set('sg', $this->SharingGroup->data);
	}
	
	public function access1() {
		debug($this->SharingGroup->checkIfAuthorised($this->Auth->user(), 15));
	}
	
	public function access2() {
		debug($this->SharingGroup->fetchAllAuthorised($this->Auth->user()));
	}
	
}
	