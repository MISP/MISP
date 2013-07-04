<?php

App::uses('AppController', 'Controller');

/**
 * Regexps Controller
 *
 * @property Regexp $Regexp
 */
class RegexpController extends AppController {

	public $components = array('Security', 'RequestHandler', 'AdminCrud');

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Regexp.id' => 'ASC'
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
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminAdd();
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
		$this->AdminCrud->adminIndex();
		//}
	}

/**
 * admin_edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function admin_edit($id = null) {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
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
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
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

/**
 *
 */
	public function admin_clean() {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
		$allRegexp = $this->Regexp->find('all');
		$this->regexpAll('Attribute', 'value', $allRegexp);
		$this->regexpAll('Event', 'info', $allRegexp);

		$this->redirect(array('action' => 'index'));
	}

	public function regexpAll($Model, $Field, $allRegexp) {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
		$deletable = array();
		$this->loadModel($Model);
		$all = $this->{$Model}->find('all', array('recursive' => -1));
		foreach ($all as $item) {
			$result = $this->__replaceSpecific($item[$Model][$Field], $allRegexp);
			if (!$result) {
				$deletable[] = $item[$Model]['id'];
			} else {
				$this->{$Model}->save($item);
			}
		}
		if (count($deletable)) {
			foreach ($deletable as $item) {
				$this->{$Model}->delete($item);
			}
		}
	}

	private function __replaceSpecific($origString, $allRegexp = null) {
		if($this->Auth->User('org') != 'ADMIN') $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
		$returnValue = true;
		foreach ($allRegexp as $regexp) {
			if (strlen($regexp['Regexp']['replacement']) && strlen($regexp['Regexp']['regexp'])) {
				$origString = preg_replace($regexp['Regexp']['regexp'], $regexp['Regexp']['replacement'], $origString);
			}
			if (!strlen($regexp['Regexp']['replacement']) && preg_match($regexp['Regexp']['regexp'], $origString)) {
				App::uses('SessionComponent', 'Controller/Component');
				SessionComponent::setFlash('Blacklisted value!');
				return false;
			}
		}
		return $returnValue;
	}
}