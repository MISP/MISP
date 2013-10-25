<?php

App::uses('AppController', 'Controller');

/**
 * Whitelists Controller
 *
 * @property Whitelist $Whitelist
 */
class WhitelistsController extends AppController {

	public $XXXcomponents = array('Security', 'RequestHandler');

	public $components = array(
		'Security',
		'AdminCrud'
	);

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Whitelist.name' => 'ASC'
			)
	);

	public function beforeFilter() { // TODO REMOVE
		parent::beforeFilter();
	}

/**
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		if(!$this->userRole['perm_regexp_access']) $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminAdd();
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		if(!$this->userRole['perm_regexp_access']) $this->redirect(array('controller' => 'whitelists', 'action' => 'index', 'admin' => false));
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
		if(!$this->userRole['perm_regexp_access']) $this->redirect(array('controller' => 'whitelists', 'action' => 'index', 'admin' => false));
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
		if(!$this->userRole['perm_regexp_access']) $this->redirect(array('controller' => 'whitelists', 'action' => 'index', 'admin' => false));
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
	}
}