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
			if (!$this->userRole['perm_sync']) $this->redirect(array('controller' => 'events', 'action' => 'index'));
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
		if ((!$this->_IsSiteAdmin()) && !($this->Server->organization == $this->Auth->user('org') && $this->userRole['perm_sync'])) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
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
		if (!$this->_IsSiteAdmin() && !($this->Server->organization == $this->Auth->user('org') && $this->userRole['perm_sync'])) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
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
		if(!$this->_IsSiteAdmin() && !($this->Server->id == $this->Auth->user('org') && $this->userRole['perm_sync'])) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
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

	/**
	 * Pull one or more events with attributes from a remote instance.
	 * Set $technique to
	 * 		full - download everything
	 * 		incremental - only new events
	 * 		<int>	- specific id of the event to pull
	 * For example to download event 10 from server 2 to /servers/pull/2/5
	 * @param int $id The id of the server
	 * @param unknown_type $technique
	 * @throws MethodNotAllowedException
	 * @throws NotFoundException
	 */
	public function pull($id = null, $technique=false) {
		if (!$this->_IsSiteAdmin() && !($this->Server->organization == $this->Auth->user('org') && $this->userRole['perm_sync'])) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
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

		$eventIds = array();
		if ("full" == $technique) {
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

			// reverse array of events, to first get the old ones, and then the new ones
			$eventIds = array_reverse($eventIds);
		} elseif ("incremental" == $technique) {
		    // TODO incremental pull
		    throw new NotFoundException('Sorry, this is not yet implemented');

		} elseif (true == $technique) {
			$eventIds[] = intval($technique);
		} else {
			$this->redirect(array('action' => 'index'));
		}

		// now process the $eventIds to pull each of the events sequentially
		if (!empty($eventIds)) {
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
							$event['Event']['distribution'] = '1';
						}
						// Distribution
						switch($event['Event']['distribution']) {
							case 1:
							case 'This community only': // backwards compatibility
								// if community only, downgrade to org only after pull
								$event['Event']['distribution'] = '0';
								break;
							case 2:
							case 'Connected communities': // backwards compatibility
								// if connected communities downgrade to community only
								$event['Event']['distribution'] = '1';
								break;
							case 'All communities': // backwards compatibility
								$event['Event']['distribution'] = '3';
								break;
							case 'Your organisation only': // backwards compatibility
								$event['Event']['distribution'] = '0';
								break;
						}

						// correct $event if just one Attribute
						if (is_array($event['Event']['Attribute']) && isset($event['Event']['Attribute']['id'])) {
							$tmp = $event['Event']['Attribute'];
							unset($event['Event']['Attribute']);
							$event['Event']['Attribute'][0] = $tmp;
						}

						if (is_array($event['Event']['Attribute'])) {
							$size = is_array($event['Event']['Attribute']) ? count($event['Event']['Attribute']) : 0;
							for ($i = 0; $i < $size; $i++) {
								if (!isset($event['Event']['Attribute'][$i]['distribution'])) { // version 1
									$event['Event']['Attribute'][$i]['distribution'] = 1;
								}
								switch($event['Event']['Attribute'][$i]['distribution']) {
									case 1:
									case 'This community only': // backwards compatibility
										// if community only, downgrade to org only after pull
										$event['Event']['Attribute'][$i]['distribution'] = '0';
										break;
									case 2:
									case 'Connected communities': // backwards compatibility
										// if connected communities downgrade to community only
										$event['Event']['Attribute'][$i]['distribution'] = '1';
										break;
									case 'All communities': // backwards compatibility
									    $event['Event']['Attribute'][$i]['distribution'] = '3';
									    break;
									case 'Your organisation only': // backwards compatibility
									    $event['Event']['Attribute'][$i]['distribution'] = '0';
									    break;
								}
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
							$passAlong = $this->Server->data['Server']['url'];
							$result = $eventsController->_add($event, $fromXml = true, $this->Server->data['Server']['organization'], $passAlong, true);
							if ($result) $successes[] = $eventId;
							else {
								$fails[$eventId] = 'Failed (partially?) because of validation errors: '. print_r($eventsController->Event->validationErrors, true);
							}
						} else {
							$result = $eventsController->_edit($event, $existingEvent['Event']['id']);
							if ($result === 'success') $successes[] = $eventId;
							else $fails[$eventId] = $result;
						}
					} else {
						// error
						$fails[$eventId] = 'failed downloading the event';
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
		}

		$this->set('successes', $successes);
		$this->set('fails', $fails);
	}

	public function push($id = null, $technique=false) {
		if ($this->Auth->user('org') != 'ADMIN' && !($this->Server->organization == $this->Auth->user('org') && $this->userRole['perm_sync'])) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
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

		if ("full" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = 0;
		} elseif ("incremental" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = $this->Server->data['Server']['lastpushedid'];
		} elseif (true == $technique) {
			$eventIds[] = array('Event' => array ('id' => intval($technique)));
		} else {
			$this->redirect(array('action' => 'index'));
		}
		if (!$eventIds) {
			$findParams = array(
			        'conditions' => array(
			                $eventid_conditions_key => $eventid_conditions_value,
			                'Event.distribution >' => 0,
			                'Event.published' => 1,
			        		'Event.attribute_count >' => 0
			        ), //array of conditions
			        'recursive' => -1, //int
			        'fields' => array('Event.id'), //array of field names
			);
			$eventIds = $this->Event->find('all', $findParams);
		}
		// now process the $eventIds to pull each of the events sequentially
		if (!empty($eventIds)) {
			$successes = array();
			$fails = array();
			$lowestfailedid = null;
			$HttpSocket = new HttpSocket();
			foreach ($eventIds as $eventId) {
				$this->Event->recursive=1;
				$event = $this->Event->findById($eventId['Event']['id']);
				unset($event['User']);
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
