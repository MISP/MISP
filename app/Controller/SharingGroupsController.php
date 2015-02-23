<?php
App::uses('AppController', 'Controller');

class SharingGroupsController extends AppController {
	public $components = array('Session', 'RequestHandler');
	
	public function beforeFilter() {
		parent::beforeFilter();
		if(!empty($this->request->params['admin']) && !$this->_isSiteAdmin()) $this->redirect('/');
	}
	
	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'SharingGroup.name' => 'ASC'
			),
			'contain' => array('SharingGroupElement' => array('Organisation'), 'Organisation'),
	);
	
	public function add() {
		if($this->request->is('post')) {
			$this->SharingGroup->create();
			$this->request->data['SharingGroup']['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
			if ($this->SharingGroup->save($this->request->data)) {
				$this->SharingGroup->SharingGroupElement->create();
				if ($this->SharingGroup->SharingGroupElement->save(array(
						'sharing_group_id' => $this->SharingGroup->id,
						'organisation_id' => $this->Auth->user('Organisation')['id'],
				))) {
					$this->Session->setFlash('The Sharing Group has been successfully added.');
					$this->redirect(array('admin' => false, 'action' => 'view', $this->SharingGroup->id));
				} else {
					$this->SharingGroup->delete($this->SharingGroup->id);
					$this->Session->setFlash('The organisation could not be added.');
				}
			} else {
				$this->Session->setFlash('The organisation could not be added.');
			}
		}
		$this->set('distributionLevels', $this->SharingGroup->distributionLevels);
	}
	
	public function edit($id) {
		$this->SharingGroup->id = $id;
		if (!$this->SharingGroup->exists()) {
			throw new NotFoundException('Invalid SharingGroup');
		}
		if ($this->request->is('post')) {
			
		}
		$this->request->data = $this->SharingGroup->read(null, $id);
		$this->SharingGroup->checkAccess($this->Auth->user(), $id);
		$this->set('distributionLevels', $this->SharingGroup->distributionLevels);
	}
	
	public function delete($id) {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('Action not allowed, post request expected.');
		$accessLevel = $this->SharingGroup->checkAccess($this->Auth->user(), $id);
		if ($accessLevel != 3) throw new MethodNotAllowedException('Action not allowed.');
		$this->SharingGroup->delete($id);
		$this->redirect('/SharingGroups/index');
	}
	
	public function index() {
		if (!$this->_isSiteAdmin()) {
			$sharingGroupIDs = $this->SharingGroup->fetchSharingGroups($this->Auth->user(), false, true);
			if (empty($sharingGroupIDs)) $sharingGroupIDs[] = '-1';
			$this->paginate['conditions'] = array('SharingGroup.id' => $sharingGroupIDs);
		}
		$result = $this->paginate();
		// check if the current user can modify or delete the SG
		foreach ($result as $k => $sg) {
			$result[$k]['access'] = $this->SharingGroup->checkAccess($this->Auth->user(), $sg['SharingGroup']['id']);
			if ($sg['SharingGroup']['organisation_uuid'] == $this->Auth->user('Organisation')['uuid']) {
				$result[$k]['editable'] = true;
			} else {
				$result[$k]['editable'] = false;
			}
		}
		$this->set('sharingGroups', $result);
		$this->set('distributionLevels', $this->SharingGroup->distributionLevels);
	}
	
	public function addElement() {
		
	}
	
	public function view($id) {
		$sharingGroupIDs = $this->SharingGroup->fetchSharingGroups($this->Auth->user(), $this->_isSiteAdmin(), true);
		if (!in_array($id, $sharingGroupIDs)) throw new MethodNotAllowedException('Sharing group doesn\'t exist or you do not have permission to access it.');
		$this->SharingGroup->id = $id;
		$this->SharingGroup->contain(array('SharingGroupElement' => array('Organisation'), 'Organisation'));
		$this->SharingGroup->read();
		debug($this->SharingGroup->data);
		$this->set('sg', $this->SharingGroup->data);
	}
	
}
	