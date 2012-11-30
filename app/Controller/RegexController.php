<?php
App::uses('AppController', 'Controller');
/**
 * Logs Controller
 *
 * @property Log $Log
 */
class RegexController extends AppController {

    public $components = array('Security', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
    		'order' => array(
                    'Regex.id' => 'ASC'
            )
    );
    public $helpers = array('Js' => array('Jquery'));

    function beforeFilter() {
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
		$this->Regex->recursive = 0;
		$this->set('regexs', $this->paginate());
	}

/**
 * add method
 *
 * @return void
 */
	public function admin_add() {
		if ($this->request->is('post')) {
			$this->Regex->create();
			if ($this->Regex->save($this->request->data)) {
				$this->Session->setFlash(__('The regex has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The regex could not be saved. Please, try again.'));
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
		$this->Regex->id = $id;
		if (!$this->Regex->exists()) {
			throw new NotFoundException(__('Invalid whitelist'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			if ($this->Regex->save($this->request->data)) {
				$this->Session->setFlash(__('The regex has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The regex could not be saved. Please, try again.'));
			}
		} else {
			$this->request->data = $this->Regex->read(null, $id);
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
		$this->Regex->id = $id;
		if (!$this->Regex->exists()) {
			throw new NotFoundException(__('Invalid regex'));
		}
		if ($this->Regex->delete()) {
			$this->Session->setFlash(__('Regex deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Regex was not deleted'));
		$this->redirect(array('action' => 'index'));
	}
}
