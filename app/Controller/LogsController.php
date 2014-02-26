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

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		if(!$this->userRole['perm_audit']) $this->redirect(array('controller' => 'events', 'action' => 'index', 'admin' => false));
		$this->set('isSearch', 0);
		if ($this->_isSiteAdmin()) {
			$this->AdminCrud->adminIndex();
		} else {
			$orgRestriction = null;
			$orgRestriction = $this->Auth->user('org');
			$conditions['Log.org LIKE'] = '%' . $orgRestriction . '%';
			$this->recursive = 0;
			$this->paginate = array(
					'limit' => 60,
					'conditions' => $conditions,
					'order' => array('Log.id' => 'DESC')
			);

			$this->set('list', $this->paginate());
		}
	}

	// Shows a minimalistic history for the currently selected event
	public function event_index($id, $org = null) {
		// check if the user has access to this event...
		$mayModify = false;
		$mineOrAdmin = false;
		$this->loadModel('Event');
		$this->Event->recursive = -1;
		$this->Event->read(null, $id);
		// send unauthorised people away. Only site admins and users of the same org may see events that are "your org only". Everyone else can proceed for all other levels of distribution
		if (!$this->_isSiteAdmin()) {
			if ($this->Event->data['Event']['distribution'] == 0) {
				if ($this->Event->data['Event']['org'] != $this->Auth->user('org')) {
					$this->Session->setFlash(__('You don\'t have access to view this event.'));
					$this->redirect(array('controller' => 'events', 'action' => 'index', 'admin' => false));
				} else {
					$mineOrAdmin = true;
				}
			}
		} else {
			$mineOrAdmin = true;
		}
		$this->set('published', $this->Event->data['Event']['published']);
		if ($mineOrAdmin && $this->userRole['perm_modify']) $mayModify = true;
		
		
		$conditions['OR'][] = array('AND' => array('Log.model LIKE' => 'Event', 'Log.model_id LIKE' => $id));
		if ($org) $conditions['AND'][] = array('Log.org LIKE' => $org, 'Log.model LIKE' => 'ShadowAttribute');
		// if we are not the owners of the event and we aren't site admins, then we should only see the entries for attributes that are not private
		// This means that we will not be able to see deleted attributes - since those could have been private
		if (!$mayModify) {
		// get a list of the attributes that belong to the event
		
			$this->loadModel('Attribute');
			$this->Attribute->recursive = -1;
			$attributes = $this->Attribute->find('all', array(
					'conditions' => array('event_id' => $id),
					'fields' => array ('id', 'event_id', 'distribution'),
					'contain' => 'Event.distribution'
			));
			// get a list of all log entries that affect the current event or any of the attributes found above
			$conditions['OR'][] = array('AND' => array ('Log.model LIKE' => 'Attribute'));
			// set a condition for the attribute, otherwise an empty event will show all attributes in the log
			$conditions['OR'][1]['AND']['OR'][0] = array('Log.model_id LIKE' => null);
			foreach ($attributes as $a) {
				// Hop over the attributes that are private if the user should is not of the same org and not an admin
				if ($mineOrAdmin || ($a['Event']['distribution'] != 0 && $a['Attribute']['distribution'] != 0)) {
					$conditions['OR'][1]['AND']['OR'][] = array('Log.model_id LIKE' => $a['Attribute']['id']);
				}
			}
		} else {
			$conditions['OR'][] = array('AND' => array ('Log.model LIKE' => 'Attribute', 'Log.title LIKE' => '%Event (' . $id . ')%'));
		}
		$conditions['OR'][] = array('AND' => array ('Log.model LIKE' => 'ShadowAttribute', 'Log.title LIKE' => '%Event (' . $id . ')%'));
		//$conditions['OR'][] = array('AND' => array ('Log.model LIKE' => 'ShadowAttribute', 'Log.title LIKE' => '%Event (' . $id . ')%'));
		$fieldList = array('title', 'created', 'model', 'model_id', 'action', 'change', 'org');
		$this->paginate = array(
				'limit' => 60,
				'conditions' => $conditions,
				'order' => array('Log.id' => 'DESC'),
				'fields' => $fieldList
		);
		$this->set('event', $this->Event->data);
		$this->set('list', $this->paginate());
		$this->set('eventId', $id);
		$this->set('mayModify', $mayModify);
	}

	public $helpers = array('Js' => array('Jquery'), 'Highlight');

	public function admin_search() {
		if(!$this->userRole['perm_audit']) $this->redirect(array('controller' => 'events', 'action' => 'index', 'admin' => false));
		$fullAddress = array('/admin/logs/search', '/logs/admin_search'); // FIXME remove this crap check
		$orgRestriction = null;
		if ($this->_isSiteAdmin()) {
			$orgRestriction = false;
		} else {
			$orgRestriction = $this->Auth->user('org');
		}
		$this->set('orgRestriction', $orgRestriction);
		if (in_array($this->request->here, $fullAddress)) { // FIXME remove this crap check

			$this->set('actionDefinitions', $this->{$this->defaultModel}->actionDefinitions);

			// reset the paginate_conditions
			$this->Session->write('paginate_conditions_log', array());

			if ($this->request->is('post') && in_array($this->request->here, $fullAddress)) { // FIXME remove this crap check
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
					$conditions['LOWER(Log.email) LIKE'] = '%' . strtolower($email) . '%';
				}
				if (isset($org)) {
					$conditions['LOWER(Log.org) LIKE'] = '%' . strtolower($org) . '%';
				}
				if ($action != 'ALL') {
					$conditions['Log.action ='] = $action;
				}
				if (isset($title)) {
					$conditions['LOWER(Log.title) LIKE'] = '%' . strtolower($title) . '%';
				}
				if (isset($change)) {
					$conditions['LOWER(Log.change) LIKE'] = '%' . strtolower($change) . '%';
				}
				$this->{$this->defaultModel}->recursive = 0;
				$this->paginate = array(
					'limit' => 60,
					'conditions' => $conditions,
					'order' => array('Log.id' => 'DESC')
				);
				$this->set('list', $this->paginate());

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
			$this->set('list', $this->paginate());

			// set the same view as the index page
			$this->render('admin_index');
		}
	}

	public function returnDates($org = 'all') {
		$data = $this->Log->returnDates($org);
		$this->set('data', $data);
		$this->set('_serialize', 'data');
	}
	
	public function maxDateActivity() {
		return $this->Log->maxDateActivity();
	}
}
