<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

/**
 * Servers Controller
 *
 * @property Server $Server
 *
 * @throws ConfigureException // TODO Exception
 */
class ServersController extends AppController {

	public $components = array('Security' ,'RequestHandler');	// XXX ACL component

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events
			'order' => array(
					'Server.url' => 'ASC'
			)
	);

	public $uses = array('Server', 'Event');

	public function beforeFilter() {
		parent::beforeFilter();

		// Disable this feature if the sync configuration option is not active
		if ('true' != Configure::read('CyDefSIG.sync'))
			throw new ConfigureException("The sync feature is not active in the configuration.");

		// permit reuse of CSRF tokens on some pages.
		switch ($this->request->params['action']) {
			case 'push':
			case 'pull':
				$this->Security->csrfUseOnce = false;
		}
	}

/**
 * index method
 *
 * @return void
 */
	public function index() {
		$this->Server->recursive = 0;
		if ($this->_IsSiteAdmin()) {
			$this->paginate = array(
							'conditions' => array(),
			);
		} else {
			if (!$this->checkAction('perm_sync')) $this->redirect(array('controller' => 'events', 'action' => 'index'));
			$conditions['Server.org LIKE'] = $this->Auth->user('org');
			$this->paginate = array(
					'conditions' => array($conditions),
			);
		}
		$this->set('servers', $this->paginate());
	}

/**
 * add method
 *
 * @return void
 */
	public function add() {
		if ((!$this->_IsSiteAdmin()) && !($this->Server->organization == $this->Auth->user('org') && $this->checkAction('perm_sync'))) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if ($this->request->is('post')) {
			// force check userid and orgname to be from yourself
			$this->request->data['Server']['org'] = $this->Auth->user('org');

			$this->Server->create();
			if ($this->Server->save($this->request->data)) {
				$this->Session->setFlash(__('The server has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The server could not be saved. Please, try again.'));
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
	public function edit($id = null) {
		if (!$this->_IsSiteAdmin() && !($this->Server->organization == $this->Auth->user('org') && $this->checkAction('perm_sync'))) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			// say what fields are to be updated
			$fieldList = array('url', 'push', 'pull', 'organization');
			if ("" != $this->request->data['Server']['authkey'])
				$fieldList[] = 'authkey';
			// Save the data
			if ($this->Server->save($this->request->data, true, $fieldList)) {
				$this->Session->setFlash(__('The server has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The server could not be saved. Please, try again.'));
			}
		} else {
			$this->Server->read(null, $id);
			$this->Server->set('authkey', '');
			$this->request->data = $this->Server->data;
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
	public function delete($id = null) {
		if(!$this->_IsSiteAdmin() && !($this->Server->id == $this->Auth->user('org') && $this->checkAction('perm_sync'))) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		if ($this->Server->delete()) {
			$this->Session->setFlash(__('Server deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Server was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

	public function pull($id = null, $full=false) {
		// TODO should we de-activate data validation for type and category / and or mapping? Maybe other instances have other configurations that are incompatible.
		if (!$this->_IsSiteAdmin() && !($this->Server->organization == $this->Auth->user('org') && $this->checkAction('perm_sync'))) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}

		App::uses('HttpSocket', 'Network/Http');
		$this->Server->read(null, $id);
		if (false == $this->Server->data['Server']['pull']) {
			$this->Session->setFlash(__('Pull setting not enabled for this server.'));
			$this->redirect(array('action' => 'index'));
		}

		if ("full" == $full) {
			// get a list of the event_ids on the server
			$eventIds = $this->Event->getEventIdsFromServer($this->Server->data);
			// FIXME this is not clean at all ! needs to be refactored with try catch error handling/communication
			if ($eventIds === 403) {
				$this->Session->setFlash(__('Not authorised. This is either due to an invalid auth key, or due to the sync user not having authentication permissions enabled on the remote server.'));
				$this->redirect(array('action' => 'index'));
			} else if (is_string($eventIds)) {
				$this->Session->setFlash($eventIds);
				$this->redirect(array('action' => 'index'));
			}

			$successes = array();
			$fails = array();
			// download each event
			if (null != $eventIds) {
				App::import('Controller', 'Events');
				$HttpSocket = new HttpSocket();
				foreach ($eventIds as &$eventId) {
					$event = $this->Event->downloadEventFromServer(
							$eventId,
							$this->Server->data);
					if (null != $event) {
						// we have an Event array
						if (!isset($event['Event']['distribution'])) { // version 1
							$event['Event']['distribution'] = 1;
						}
						// Distribution
						switch($event['Event']['distribution']) {
							case 1:
								// if community only, downgrade to org only after pull
								$event['Event']['distribution'] = 0;
								break;
							case 2:
								// if connected communities downgrade to community only
								$event['Event']['distribution'] = 1;
								break;
						}

						// correct $event if just one Attribute
						if (is_array($event['Event']['Attribute']) && isset($event['Event']['Attribute']['id'])) {
							$tmp = $event['Event']['Attribute'];
							unset($event['Event']['Attribute']);
							$event['Event']['Attribute'][0] = $tmp;
						}

						if (is_array($event['Event']['Attribute'])) {
							$toRemove = array();
							$size = is_array($event['Event']['Attribute']) ? count($event['Event']['Attribute']) : 0;
							for ($i = 0; $i < $size; $i++) {
								if (!isset($event['Event']['Attribute'][$i]['distribution'])) { // version 1
									$event['Event']['Attribute'][$i]['distribution'] = 1;
								}
								switch($event['Event']['Attribute'][$i]['distribution']) {
									case 1:
										// if community only, downgrade to org only after pull
										$event['Event']['Attribute'][$i]['distribution'] = 0;
										break;
									case 2:
										// if connected communities downgrade to community only
										$event['Event']['Attribute'][$i]['distribution'] = 1;
										break;
								}
							}
							foreach ($toRemove as $thisRemove) {
								unset($event['Event']['Attribute'][$thisRemove]);
							}
							$event['Event']['Attribute'] = array_values($event['Event']['Attribute']);
						} else {
							unset($event['Event']['Attribute']);
						}
						// Distribution, set reporter of the event, being the admin that initiated the pull
						$event['Event']['user_id'] = $this->Auth->user('id');
						// check if the event already exist (using the uuid)
						$existingEvent = null;
						$existingEvent = $this->Event->find('first', array('conditions' => array('Event.uuid' => $event['Event']['uuid'])));
						$eventsController = new EventsController();
						$eventsController->constructClasses();
						if (!$existingEvent) {
							// add data for newly imported events
							$event['Event']['info'] .= "\n Imported from " . $this->Server->data['Server']['url'];
							$passAlong = $this->Server->data['Server']['url'];
							try {
								$result = $eventsController->_add($event, $fromXml = true, $this->Server->data['Server']['organization'], $passAlong, true);
							} catch (MethodNotAllowedException $e) {
								if ($e->getMessage() == 'Event already exists') {
									//$successes[] = $eventId;	// commented given it's in a catch..
									continue;
								}
							}
							if ($result) $successes[] = $eventId;
							else $fails[$eventId] = 'failed';
						} else {
							$result = $eventsController->_edit($event, $existingEvent['Event']['id']);
							if ($result === 'success') $successes[] = $eventId;
							else $fails[$eventId] = $result;
						}
					} else {
						// error
						$fails[$eventId] = 'failed';
					}

				}
				if (count($fails) > 0) {
					// there are fails, take the lowest fail
					$lastpulledid = min(array_keys($fails));
				} else {
					// no fails, take the highest success
					$lastpulledid = count($successes) > 0 ? max($successes) : 0;
				}
				// increment lastid based on the highest ID seen
				$this->Server->set('lastpulledid', $lastpulledid);
				$this->Server->save($event, array('fieldList' => array('lastpulledid', 'url')));

			}

		} else {
			// TODO incremental pull
			// lastpulledid
			throw new NotFoundException('Sorry, this is not yet implemented');

			// increment lastid based on the highest ID seen
		}

		$this->set('successes', $successes);
		$this->set('fails', $fails);
	}

	public function push($id = null, $full=false) {
		if ($this->Auth->user('org') != 'ADMIN' && !($this->Server->organization == $this->Auth->user('org') && $this->checkAction('perm_sync'))) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}

		App::uses('HttpSocket', 'Network/Http');
		$this->Server->read(null, $id);

		if (false == $this->Server->data['Server']['push']) {
			$this->Session->setFlash(__('Push setting not enabled for this server.'));
			$this->redirect(array('action' => 'index'));
		}

		if ("full" == $full) $lastpushedid = 0;
		else $lastpushedid = $this->Server->data['Server']['lastpushedid'];

		$findParams = array(
				'conditions' => array(
						'Event.id >' => $lastpushedid, // TODO think about this one!!
						'Event.private' => 0,
						'Event.published' => 1
						), //array of conditions
				'recursive' => 1, //int
				'fields' => array('Event.*'), //array of field names
		);
		$events = $this->Event->find('all', $findParams);

		// FIXME now all events are uploaded, even if they exist on the remote server. No merging is done

		$successes = array();
		$fails = array();
		$lowestfailedid = null;

		if (!empty($events)) { // do nothing if there are no events to push
			$HttpSocket = new HttpSocket();

			$this->loadModel('Attribute');
			// upload each event separately and keep the results in the $successes and $fails arrays
			foreach ($events as &$event) {
				$result = $this->Event->uploadEventToServer(
						$event,
						$this->Server->data,
						$HttpSocket);
				if (true == $result) {
					$successes[] = $event['Event']['id'];
				} else {
					$fails[$event['Event']['id']] = $result;
				}
			}
			if (count($fails) > 0) {
				// there are fails, take the lowest fail
				$lastpushedid = min(array_keys($fails));
			} else {
				// no fails, take the highest success
				$lastpushedid = max($successes);
			}
			// increment lastid based on the highest ID seen
			$this->Server->saveField('lastpushedid', $lastpushedid);
		}
		$this->set('successes', $successes);
		$this->set('fails', $fails);
	}
}
