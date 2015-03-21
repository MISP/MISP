<?php
App::uses('AppController', 'Controller');

class OrganisationsController extends AppController {
	public $components = array('Session', 'RequestHandler');
	
	public function beforeFilter() {
		parent::beforeFilter();
		if(!empty($this->request->params['admin']) && !$this->_isSiteAdmin()) $this->redirect('/');
	}
	
	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'Organisation.name' => 'ASC'
			),
	);
	
	public function index($local = true) {
		// We can either index all of the organisations existing on this instance (default)
		// or we can pass the 'external' keyword in the URL to look at the added external organisations
		if ($local === 'external') $local = false;
		$this->paginate['conditions'] = array('Organisation.local' => $local);
		$orgs = $this->paginate();
		if ($this->_isSiteAdmin()) {
			$this->loadModel('User');
			$org_creator_ids = array();
			foreach ($orgs as $org) {
				if (!in_array($org['Organisation']['created_by'], $org_creator_ids)) {
					$email = $this->User->find('first', array('recursive' => -1, 'fields' => array('id', 'email'), 'conditions' => array('id' => $org['Organisation']['created_by'])));
					if (!empty($email)) {
						$org_creator_ids[$org['Organisation']['created_by']] = $email['User']['email'];
					} else {
						$org_creator_ids[$org['Organisation']['created_by']] = 'Unknown';
					}
				}
			}	
			$this->set('org_creator_ids', $org_creator_ids);
		}
		$this->set('local', $local);
		$this->set('orgs', $orgs);
	}
	
	public function admin_add() {
		if($this->request->is('post')) {
			$this->Organisation->create();
			$date = date('Y-m-d H:i:s');
			$this->request->data['Organisation']['date_created'] = $date;
			$this->request->data['Organisation']['date_modified'] = $date;
			$this->request->data['Organisation']['created_by'] = $this->Auth->user('id');
			if ($this->Organisation->save($this->request->data)) {
				$this->Session->setFlash('The organisation has been successfully added.');
				$this->redirect(array('admin' => false, 'action' => 'index'));
				//$this->redirect(array('admin' => false, 'action' => 'view', $this->Organisation->id));
			} else {
				$this->Session->setFlash('The organisation could not be added.');
			}
		}
		$this->set('countries', $this->_arrayToValuesIndexArray($this->Organisation->countries));
	}
	
	public function admin_edit($id) {
		$this->Organisation->id = $id;
		if (!$this->Organisation->exists()) {
			throw new NotFoundException('Invalid organisation');
		}
		if (!$this->Organisation->exists()) throw new NotFoundException('Invalid organisation');
		if ($this->request->is('post') || $this->request->is('put')) {
			if ($this->Organisation->save($this->request->data)) {
				$this->Session->setFlash('Organisation updated.');
				$this->redirect(array('admin' => false, 'action' => 'view', $this->Organisation->id));
			} else {
				$this->Session->setFlash('The organisation could not be updated.');
			}
		} else {
			$this->set('countries', $this->_arrayToValuesIndexArray($this->Organisation->countries));
		}
		$this->Organisation->read(null, $id);
		$this->set('orgId', $id);
		$this->request->data = $this->Organisation->data;
	}
	
	public function admin_delete($id) {
		$this->Organisation->id = $id;
		if (!$this->Organisation->exists()) throw new NotFoundException('Invalid organisation');
		if ($this->Organisation->delete()) {
			$this->Session->setFlash(__('Organisation deleted'));
			$this->redirect(array('admin' => false, 'action' => 'index'));
		} else {
			$this->Session->setFlash(__('Organisation could not be deleted. Make sure that there are no users still tied to this organisation before deleting it.'));
			$this->redirect(array('admin' => false, 'action' => 'index'));
		}
	}
	
	public function admin_generateuuid() {
		$this->set('uuid', String::uuid());
		$this->set('_serialize', array('uuid'));
	}
	
	public function view($id) {
		$this->Organisation->id = $id;
		if (!$this->Organisation->exists()) throw new NotFoundException('Invalid organisation');
		$fullAccess = false;
		$fields = array('id', 'name', 'date_created', 'date_modified', 'type', 'nationality', 'sector', 'contacts', 'description');
		if ($this->_isSiteAdmin() || $this->Auth->user('Organisation')['id'] == $id) {
			$fullAccess = true;
			$fields = array_merge($fields, array('created_by', 'uuid'));
		}
		$org = $this->Organisation->find('first', array(
				'conditions' => array('id' => $id),
				'fields' => $fields
		));
		$member_count = $this->Organisation->User->find('count', array('conditions' => array('organisation_id' => $id)));
		
		if ($fullAccess) {
			$creator = $this->Organisation->User->find('first', array('conditions' => array('User.id' => $org['Organisation']['created_by'])));
			$this->set('creator', $creator);
		}
		$this->set('fullAccess', $fullAccess);
		$this->set('org', $org);
		$this->set('member_count', $member_count);
		$this->set('id', $id);
	}
	
	public function landingpage($id) {
		$this->Organisation->id = $id;
		if (!$this->Organisation->exists()) throw new NotFoundException('Invalid organisation');
		$org = $this->Organisation->find('first', array('conditions' => array('id' => $id), 'fields' => array('landingpage', 'name')));
		$landingpage = $org['Organisation']['landingpage'];
		if (empty($landingpage)) $landingpage = "No landing page has been created for this organisation.";
		$this->set('landingPage', $landingpage);
		$this->set('org', $org['Organisation']['name']);
		$this->render('ajax/landingpage');
	}
}