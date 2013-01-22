<?php

App::uses('AppController', 'Controller');

/**
 * Roles Controller
 *
 * @property Role $Role
 */
class RolesController extends AppController {

	public $options = array('0' => 'Read Only', '1' => 'Manage My Own Events', '2' => 'Manage Organization Events', '3' => 'Manage &amp; Publish Organization Events');

	public $components = array(
		'Acl',
		'Auth' => array(
			'authorize' => array(
				'Actions' => array('actionPath' => 'controllers/Roles')
			)
		),
		'Security',
		'Session', 'AdminCrud' // => array('fields' => array('name'))
	);

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
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		$this->AdminCrud->adminAdd();
		$this->set('options', $this->options);
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
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
		$this->AdminCrud->adminEdit($id);
		$this->set('options', $this->options);
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
}