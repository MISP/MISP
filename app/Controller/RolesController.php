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
		'Session', 'AdminCrud' // => array('fields' => array('name'))
	);

	public $helpers = array('Js' => array('Jquery'));

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
 * @return void
 *
 * @throws NotFoundException
 */
	public function view($id = null) {
		$this->Role->id = $id;
		//$this->Acl->allow($this->Role, 'controllers/Events/add');
		if (!$this->Role->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		$this->set('role', $this->Role->read(null, $id));
		$this->set('id', $id);
	}

/**
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		if(!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
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
		$this->set('options', $this->options);
		//$this->AdminCrud->adminAdd();
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		if(!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminIndex();
		$this->set('options', $this->options);
	}

/**
 * admin_edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function admin_edit($id = null) {
		if(!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminEdit($id);
		$passAlong = $this->Role->read(null, $id);
		$this->set('options', $this->options);
		$this->set('id', $id);
	}

/**
 * admin_delete method
 *
 * @param string $id
 *
 * @throws MethodNotAllowedException
 * @throws NotFoundException
 *
 * @return void
 */
	public function admin_delete($id = null) {
		$this->AdminCrud->adminDelete($id);
	}

/**
 * index method
 *
 * @return void
 */
	public function index() {
		$this->recursive = 0;
		$this->set('list', $this->paginate());
		$this->set('options', $this->options);
	}
}
