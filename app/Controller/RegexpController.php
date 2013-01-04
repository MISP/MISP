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

	public function isAuthorized($user) {
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
		$this->AdminCrud->adminAdd();
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
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
		$this->AdminCrud->adminDelete($id);
	}

/**
 *
 */
	public function admin_clean() {
		$this->regexpAll('Attribute', 'value');
		$this->regexpAll('Event', 'info');

		$this->redirect(array('action' => 'index'));
	}

	public function regexpAll($Model, $Field) {
		$deletable = array();
		$this->loadModel($Model);
		$all = $this->{$Model}->find('all', array('recursive' => -1));
		foreach ($all as $item) {
			$result = $this->replaceSpecific($item[$Model][$Field]);
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

	public function replaceSpecific($origString) {
		$returnValue = true;
		$allRegexp = $this->Regexp->find('all'); // TODO REGEXP INIT LOAD ARRAY
		foreach ($allRegexp as $regexp) {
			if (strlen($regexp['Regexp']['replacement']) && strlen($regexp['Regexp']['regexp'])) {
				$origString = preg_replace($regexp['Regexp']['regexp'], $regexp['Regexp']['replacement'], $origString);
			}
			if (!strlen($regexp['Regexp']['replacement']) && preg_match($regexp['Regexp']['regexp'], $origString)) {
				App::uses('SessionComponent', 'Controller/Component');
				SessionComponent::setFlash('Blacklisted value!');
				$returnValue = false;
			}
		}
		return $returnValue;
	}

}