<?php
App::uses('AppController', 'Controller');
/**
 * Logs Controller
 *
 * @property Log $Log
 */
class RegexpController extends AppController {

	public $components = array('Security', 'RequestHandler');

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Regexp.id' => 'ASC'
			)
	);

	public function beforeFilter() {
		parent::beforeFilter();

		// permit reuse of CSRF tokens on the search page.
		if ('search' == $this->request->params['action']) {
			$this->Security->csrfUseOnce = false;
		}
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
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		$this->Regexp->recursive = 0;
		$this->set('regexps', Sanitize::clean($this->paginate()));
	}

/**
 * add method
 *
 * @return void
 */
	public function admin_add() {
		if ($this->request->is('post')) {
			$this->Regexp->create();
			if ($this->Regexp->save($this->request->data)) {
				$this->Session->setFlash(__('The regexp has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The regexp could not be saved. Please, try again.'));
			}
		}
	}

/**
 * edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function admin_edit($id = null) {
		$this->Regexp->id = $id;
		if (!$this->Regexp->exists()) {
			throw new NotFoundException(__('Invalid whitelist'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			if ($this->Regexp->save($this->request->data)) {
				$this->Session->setFlash(__('The regexp has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The regexp could not be saved. Please, try again.'));
			}
		} else {
			$this->request->data = Sanitize::clean($this->Regexp->read(null, $id));
		}
	}

/**
 * delete method
 *
 * @param string $id
 * @return void
 * @throws MethodNotAllowedException
 * @throws NotFoundException
 */
	public function admin_delete($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Regexp->id = $id;
		if (!$this->Regexp->exists()) {
			throw new NotFoundException(__('Invalid regexp'));
		}
		if ($this->Regexp->delete()) {
			$this->Session->setFlash(__('Regexp deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Regexp was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

/**
 *
 */
	public function admin_clean() {
		// Attributes.value
		$deletableAttributes = array();
		$this->loadModel('Attribute');
		$attributes = $this->Attribute->find('all', array('recursive' => 0));
		foreach ($attributes as $attribute) {
			$result = $this->replaceSpecific($attribute['Attribute']['value']);
			if (!$result) {
				$deletableAttributes[] = $attribute['Attribute']['id'];
			} else {
				$this->Attribute->save($attribute);
			}
		}
		if (count($deletableAttributes)) {
			foreach ($deletableAttributes as $event) {
				$this->Attribute->delete($event);
			}
		}

		// Event.info
		$deletableEvents = array();
		$this->loadModel('Event');
		$events = $this->Event->find('all', array('recursive' => 0));
		foreach ($events as $event) {
			$result = $this->replaceSpecific($event['Event']['info']);
			if (!$result) {
				$deletableEvents[] = $event['Event']['id'];
			} else {
				$this->Event->save($event);
			}
		}
		if (count($deletableEvents)) {
			foreach ($deletableEvents as $event) {
				$this->Event->delete($event);
			}
		}

		$this->redirect(array('action' => 'index'));
	}

	public function replaceSpecific($origString) {
		$returnValue = true;
		$regexp = new Regexp();
		$allRegexp = $regexp->getAll();
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