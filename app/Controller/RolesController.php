<?php
App::uses('AppController', 'Controller');
/**
 * Roles Controller
 *
 * @property Role $Role
 */
class RolesController extends AppController {

	public $options = array('0' => 'Read Only', '1' => 'Manage My Own Events', '2' => 'Manage Organization Events', '3' => 'Manage & Publish Organization Events');

	public $components = array(
		'Acl',
		'Auth' => array(
			'authorize' => array(
				'Actions' => array('actionPath' => 'controllers/Roles')
			)
		),
		'Security',
		'Session'
	);

	//public $components = array('Security');
	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Role.name' => 'ASC'
			)
	);

	public function beforeFilter() {
		parent::beforeFilter();
	}

/**
 * view method
 *
 * @param string $id
 *
 * @throws NotFoundException
 *
 * @return void
 */
	public function view($id = null) {
		$this->Role->id = $id;
		if (!$this->Role->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		$this->set('role', Sanitize::clean($this->Role->read(null, $id)));
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		$this->Role->recursive = 0;
		$this->set('roles', Sanitize::clean($this->paginate()));
		$this->set('options', $this->options);
	}

/**
 * admin_view method
 *
 * @param string $id
 *
 * @throws NotFoundException
 *
 * @return void
 */
	public function admin_view($id = null) {
		$this->Role->id = $id;
		if (!$this->Role->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		$this->set('role', Sanitize::clean($this->Role->read(null, $id)));
	}

/**
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		if ($this->request->is('post')) {
			$this->Role->create();
			$this->request->data = $this->Role->massageData($this->request->data);
			if ($this->Role->save($this->request->data)) {
				$this->saveAcl($this->Role, $this->data['Role']['perm_add'], $this->data['Role']['perm_modify'], $this->data['Role']['perm_publish']);	// save to ACL as well
				$this->Session->setFlash(__('The role has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The role could not be saved. Please, try again.'));
			}
		}
		$this->set('options', $this->options);
	}

/**
 * admin_edit method
 *
 * @param string $id
 *
 * @throws NotFoundException
 *
 * @return void
 */
	public function admin_edit($id = null) {
		$this->Role->id = $id;
		if (!$this->Role->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			$fields = array();
			$this->request->data = $this->Role->massageData($this->request->data);
			if ($this->Role->save($this->request->data, true, $fields)) {
				$this->saveAcl($this->Role, $this->data['Role']['perm_add'], $this->data['Role']['perm_modify'], $this->data['Role']['perm_publish']);	// save to ACL as well
				$this->Session->setFlash(__('The role has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The role could not be saved. Please, try again.'));
			}
		} else {
			$this->Role->recursive = 0;
			$this->Role->read(null, $id);
			$this->request->data = Sanitize::clean($this->Role->data);
		}
		$this->set('options', $this->options);
	}

/**
 * admin_delete method
 *
 * @param string $id
 *
 * @throws NotFoundException
 *
 * @return void
 */
	public function admin_delete($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Role->id = $id;
		if (!$this->Role->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		if ($this->Role->delete(null, false)) {
			$this->Session->setFlash(__('Role deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Role was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

/**
 * saveAcl method
 *
 * @param string $id
 * @return void
 */
	public function saveAcl($role, $permAdd = false, $permModify = false, $permPublish = false) {
		// this all could need some 'if-changed then do'

		if ($permAdd) {
			$this->Acl->allow($role, 'controllers/Events/add');
			$this->Acl->allow($role, 'controllers/Attributes/add');
		} else {
			$this->Acl->deny($role, 'controllers/Events/add');
			$this->Acl->deny($role, 'controllers/Attributes/add');
		}
		if ($permModify) {
			$this->Acl->allow($role, 'controllers/Events/edit');
			$this->Acl->allow($role, 'controllers/Attributes/edit');
		} else {
			$this->Acl->deny($role, 'controllers/Events/edit');
			$this->Acl->deny($role, 'controllers/Attributes/edit');
		}
		if ($permPublish) {
			$this->Acl->allow($role, 'controllers/Events/publish');
		} else {
			$this->Acl->deny($role, 'controllers/Events/publish');
		}
	}
}
