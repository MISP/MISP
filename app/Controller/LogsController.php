<?php

App::uses('AppController', 'Controller');

/**
 * Logs Controller
 *
 * @property Log $Log
 */
class LogsController extends AppController {

	public $components = array(
		'Security',
		'RequestHandler',
		'AdminCrud' => array(
			'crud' => array('index')
		)
	);

	public $paginate = array(
		'limit' => 60,
		'order' => array(
			'Log.id' => 'DESC'
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
		$this->set('isSearch', 0);
		if ($this->Auth->user('org') == 'ADMIN') {
			$this->AdminCrud->adminIndex();
		} else {
			$orgRestriction = null;
			$orgRestriction = $this->Auth->user('org');
			$conditions['Log.org LIKE'] = '%' . $orgRestriction . '%';
			$this->recursive = 0;
			$this->paginate = array(
					'limit' => 60,
					'maxLimit' => 9999,  // LATER we will bump here on a problem once we have more than 9999 logs(?)
					'conditions' => $conditions
			);

			$this->set('list', Sanitize::clean($this->paginate()));
		}
	}

	public $helpers = array('Js' => array('Jquery'));

	public function admin_search() {
		$fullAddress = array('/admin/logs/search', '/logs/admin_search');
		$orgRestriction = null;
		if ($this->Auth->user('org') == 'ADMIN') {
			$orgRestriction = false;
		} else {
			$orgRestriction = $this->Auth->user('org');
		}
		$this->set('orgRestriction', $orgRestriction);
		if (in_array($this->request->here, $fullAddress)) {

			$this->set('actionDefinitions', $this->{$this->defaultModel}->actionDefinitions);

			// reset the paginate_conditions
			$this->Session->write('paginate_conditions_log', array());

			if ($this->request->is('post') && in_array($this->request->here, $fullAddress)) {
				$email = $this->request->data['Log']['email'];
				if (!$orgRestriction) {
					$org = $this->request->data['Log']['org'];
				} else {
					$org = $this->Auth->user('org');
				}
				$action = $this->request->data['Log']['action'];
				$title = $this->request->data['Log']['title'];
				$change = $this->request->data['Log']['change'];

				// for info on what was searched for
				$this->set('emailSearch', $email);
				$this->set('orgSearch', $org);
				$this->set('actionSearch', $action);
				$this->set('titleSearch', $title);
				$this->set('changeSearch', $change);
				$this->set('isSearch', 1);

				// search the db
				$conditions = array();
				if ($email) {
					$conditions['Log.email LIKE'] = '%' . $email . '%';
				}
				if ($org) {
					$conditions['Log.org LIKE'] = '%' . $org . '%';
				}
				if ($action != 'ALL') {
					$conditions['Log.action ='] = $action;
				}
				if ($title) {
					$conditions['Log.title LIKE'] = '%' . $title . '%';
				}
				if ($change) {
					$conditions['Log.change LIKE'] = '%' . $change . '%';
				}
				$this->{$this->defaultModel}->recursive = 0;
				$this->paginate = array(
					'limit' => 60,
					'maxLimit' => 9999,  // LATER we will bump here on a problem once we have more than 9999 logs(?)
					'conditions' => $conditions
				);
				$this->set('list', Sanitize::clean($this->paginate()));

				// and store into session
				$this->Session->write('paginate_conditions_log', $this->paginate);
				$this->Session->write('paginate_conditions_log_email', $email);
				$this->Session->write('paginate_conditions_log_org', $org);
				$this->Session->write('paginate_conditions_log_action', $action);
				$this->Session->write('paginate_conditions_log_title', $title);
				$this->Session->write('paginate_conditions_log_change', $change);

				// set the same view as the index page
				$this->render('admin_index');
			} else {
				// no search keyword is given, show the search form

				// combobox for actions
				$actions = array('' => array('ALL' => 'ALL'), 'actions' => array());
				$actions['actions'] = array_merge($actions['actions'], $this->_arrayToValuesIndexArray($this->{$this->defaultModel}->validate['action']['rule'][1]));
				$this->set('actions', $actions);
			}
		} else {
			$this->set('actionDefinitions', $this->{$this->defaultModel}->actionDefinitions);

			// get from Session
			$email = $this->Session->read('paginate_conditions_log_email');
			$org = $this->Session->read('paginate_conditions_log_org');
			$action = $this->Session->read('paginate_conditions_log_action');
			$title = $this->Session->read('paginate_conditions_log_title');
			$change = $this->Session->read('paginate_conditions_log_change');

			// for info on what was searched for
			$this->set('emailSearch', $email);
			$this->set('orgSearch', $org);
			$this->set('actionSearch', $action);
			$this->set('titleSearch', $title);
			$this->set('changeSearch', $change);
			$this->set('isSearch', 1);

			// re-get pagination
			$this->{$this->defaultModel}->recursive = 0;
			$this->paginate = $this->Session->read('paginate_conditions_log');
			$this->set('list', Sanitize::clean($this->paginate()));

			// set the same view as the index page
			$this->render('admin_index');
		}
	}
}
