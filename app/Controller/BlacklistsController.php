<?php

App::uses('AppController', 'Controller');

/**
 * Blacklists Controller
 *
 * @property Blacklist $Blacklist
 */
class BlacklistsController extends AppController {

	public $XXXcomponents = array('Security', 'RequestHandler');

	public $components = array(
		'Auth' => array(
			'authorize' => array(
				'Actions' => array('actionPath' => 'controllers/Blacklists')
			)
		),
		'Security',
		'AdminCrud'
	);

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Blacklist.name' => 'ASC'
			)
	);

	public function beforeFilter() { // TODO REMOVE
		parent::beforeFilter();
	}

	public function isAuthorized($user) { // TODO REMOVE
		// Admins can access everything
		if (parent::isAuthorized($user)) {
			return true;
		}
		// the other pages are allowed by logged in users
		return true;
	}

/**
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'blacklists', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminAdd();
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'blacklists', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminIndex();
	}

/**
 * admin_edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function admin_edit($id = null) {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'blacklists', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminEdit($id);
	}

/**
 * admin_delete method
 *
 * @param string $id
 * @return void
 * @throws MethodNotAllowedException
 * @throws NotFoundException
 */
	public function admin_delete($id = null) {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'blacklists', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminDelete($id);
	}

/**
 * index method
 *
 * @return void
 */
	public function index() {
		$this->recursive = 0;
		$this->set('list', Sanitize::clean($this->paginate()));
	}
}