	<?php
App::uses('AppController', 'Controller');

class GalaxiesController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'contain' => array(
				
			),
			'order' => array(
				'Galaxy.id' => 'DESC'
			),
	);

	public function index() {
		$galaxies = $this->paginate();
		$this->set('list', $galaxies);
	}

	public function update() {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This action is only accessible via POST requests.');
		$result = $this->Galaxy->update();
		$this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
	}

	public function toggleEnable() {
		$id = $this->request->data['Warninglist']['data'];
		if (!is_numeric($id)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist not found.')), 'status' => 200));
		$currentState = $this->Warninglist->find('first', array('conditions' => array('id' => $id), 'recursive' => -1));
		if (empty($currentState)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist not found.')), 'status' => 200));
		if ($currentState['Warninglist']['enabled']) {
			$currentState['Warninglist']['enabled'] = 0;
			$message = 'disabled';
		} else {
			$currentState['Warninglist']['enabled'] = 1;
			$message = 'enabled';
		}
		if ($this->Warninglist->save($currentState)) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Warninglist ' . $message)), 'status' => 200));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist could not be enabled.')), 'status' => 200));
		}
	}

	public function enableWarninglist($id, $enable = false) {
		$this->Warninglist->id = $id;
		debug($id);
		if (!$this->Warninglist->exists()) throw new NotFoundException('Invalid Warninglist.');
		// DBMS interoperability: convert boolean false to integer 0 so cakephp doesn't try to insert an empty string into the database
		if ($enable === false) $enable = 0;
		$this->Warninglist->saveField('enabled', $enable);
		$this->Session->setFlash('Warninglist enabled');
		$this->redirect(array('controller' => 'warninglists', 'action' => 'view', $id));
	}

	public function getToggleField() {
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This action is available via AJAX only.');
		$this->layout = 'ajax';
		$this->render('ajax/getToggleField');
	}

	public function view($id) {
		if (!is_numeric($id)) throw new NotFoundException('Invalid galaxy.');
		if ($this->_isRest()) {
			$galaxy = $this->Galaxy->find('first', array(
					'contain' => array('GalaxyCluster' => array('GalaxyElement'/*, 'GalaxyReference'*/)),
					'recursive' => -1,
					'conditions' => array('Galaxy.id' => $id) 
			));
			if (empty($galaxy)) {
				throw new NotFoundException('Galaxy not found.');
			}
			$this->set('Galaxy', $galaxy);
			$this->set('_serialize', array('Galaxy'));
		} else {
			$galaxy = $this->Galaxy->find('first', array(
					'recursive' => -1,
					'conditions' => array('Galaxy.id' => $id)
			));
			if (empty($galaxy)) {
				throw new NotFoundException('Galaxy not found.');
			}
			$this->set('galaxy', $galaxy);
		}
	}
}
