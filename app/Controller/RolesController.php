<?php

App::uses('AppController', 'Controller');

/**
 * Roles Controller
 *
 * @property Role $Role
 */
class RolesController extends AppController {

	public $options = array('0' => 'Read Only', '1' => 'Manage My Own Events', '2' => 'Manage Organization Events', '3' => 'Manage & Publish Organization Events'); // FIXME move this to Role Model

	public $components = array(
		'Security',
		'Session',
		'AdminCrud' // => array('fields' => array('name'))
	);

	public $helpers = array('Js' => array('Jquery'));

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Role.name' => 'ASC'
			)
	);

	public function view($id = null) {
		$this->Role->id = $id;
		if (!$this->Role->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		$this->set('premissionLevelName', $this->Role->premissionLevelName);
		$this->set('role', $this->Role->read(null, $id));
		$this->set('id', $id);
	}

	public function admin_add() {
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		if ($this->request->is('post')) {
			$this->Role->create();
			if ($this->Role->save($this->request->data)) {
				$this->Session->setFlash(__(sprintf('The Role has been saved.')));
				$this->set('options', $this->options);
				$passAlong = $this->Role->read(null, $this->Role->getInsertID());
				$this->redirect(array('action' => 'index'));
			} else {
				if (!($this->Session->check('Message.flash'))) {
					$this->Role->Session->setFlash(__(sprintf('The Role could not be saved. Please, try again.')));
				}
			}
		}
		$this->set('permFlags', $this->Role->permFlags);
		$this->set('options', $this->options);
	}

	public function admin_index() {
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminIndex();
		$this->loadModel('AdminSetting');
		$this->set('default_role_id', $this->AdminSetting->getSetting('default_role'));
		$this->set('permFlags', $this->Role->permFlags);
		$this->set('options', $this->options);
	}

	public function admin_edit($id = null) {
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminEdit($id);
		$passAlong = $this->Role->read(null, $id);
		$this->set('options', $this->options);
		$this->set('permFlags', $this->Role->permFlags);
		$this->set('id', $id);
	}

	public function admin_delete($id = null) {
		$this->AdminCrud->adminDelete($id);
	}

	public function index() {
		$this->recursive = 0;
		$this->set('permFlags', $this->Role->permFlags);
		$this->set('list', $this->paginate());
		$this->loadModel('AdminSetting');
		$this->set('default_role_id', $this->AdminSetting->getSetting('default_role'));
		$this->set('options', $this->options);
	}

	public function admin_set_default($role_id = false) {
		if (!is_numeric($role_id) && $role_id !== false) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid role.')),'status'=>200));
		}
		$this->loadModel('AdminSetting');
		$result = $this->AdminSetting->changeSetting('default_role', $role_id);
		if ($result === true) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $role_id ? 'Default role set.' : 'Default role unset.')),'status'=>200));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $result)),'status'=>200));
		}
	}
}
