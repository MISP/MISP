<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

/**
 * Servers Controller
 *
 * @property Server $Server
 */
class ServersController extends AppController {

    public $components = array('Acl' ,'Security' ,'RequestHandler');	// XXX ACL component
    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,  // LATER we will bump here on a problem once we have more than 9999 events
            'order' => array(
                    'Server.url' => 'ASC'
            )
    );

    public $uses = array('Server', 'Event');

    function beforeFilter() {
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

    public function isAuthorized($user) {
        // Admins can access everything
        if (parent::isAuthorized($user)) {
            return true;
        }
        // Only on own servers for these actions
        if (in_array($this->action, array('edit', 'delete', 'pull'))) {
            $serverid = $this->request->params['pass'][0];
            return $this->Server->isOwnedByOrg($serverid, $this->Auth->user('org'));
        }
        // the other pages are allowed by logged in users
        return true;
    }

/**
 * index method
 *
 * @return void
 */
	public function index() {
		$this->Server->recursive = 0;

		$this->paginate = array(
		        'conditions' => array('Server.org' => $this->Auth->user('org')),
		);
		$this->set('servers', $this->paginate());
	}

/**
 * add method
 *
 * @return void
 */
	public function add() {
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
 */
	public function edit($id = null) {
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		// only edit own servers verified by isAuthorized

		if ($this->request->is('post') || $this->request->is('put')) {
		    // say what fields are to be updated
		    $fieldList=array('url', 'push', 'pull');
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
 */
	public function delete($id = null) {
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

        if ("full"==$full) {
            // get a list of the event_ids on the server
            $event_ids = $this->Event->getEventIdsFromServer($this->Server->data);

            $successes = array();
            $fails = array();
            // download each event
            if (null != $event_ids) {
                App::import('Controller', 'Events');
                $HttpSocket = new HttpSocket();
                foreach ($event_ids as $event_id) {
                    $event = $this->Event->downloadEventFromServer(
                            $event_id,
                            $this->Server->data);
                    if (null != $event) {
                        // we have an Event array
                        $event['Event']['private'] = true;
                        $event['Event']['info'] .= "\n Imported from ".$this->Server->data['Server']['url'];
                        $eventsController = new EventsController();
                        try {
                            $result = $eventsController->_add($event, $this->Auth, $fromXml=true);
                        } catch (MethodNotAllowedException $e) {
                            if ($e->getMessage() == 'Event already exists') {
                                $successes[] = $event_id;
                                continue;
                            }
                        }
                        //$result = $this->_importEvent($event);
                        // TODO error handling
                    } else {
                        // error
                        $fails[$event_id] = 'failed';
                    }

                }
                if (sizeof($fails) > 0) {
                    // there are fails, take the lowest fail
                    $lastpulledid = min(array_keys($fails));
                } else {
                    // no fails, take the highest success
                    $lastpulledid = max($successes);
                }
                // increment lastid based on the highest ID seen
                $this->Server->saveField('lastpulledid', $lastpulledid);

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

        if ("full"==$full) $lastpushedid = 0;
        else $lastpushedid = $this->Server->data['Server']['lastpushedid'];

        $find_params = array(
                'conditions' => array(
                        'Event.id >' => $lastpushedid,
                        'Event.private' => 0,
                        'Event.published' =>1
                        ), //array of conditions
                'recursive' => 1, //int
                'fields' => array('Event.*'), //array of field names
        );
        $events = $this->Event->find('all', $find_params);

// FIXME now all events are uploaded, even if they exist on the remote server. No merging is done

        $successes = array();
        $fails = array();
        $lowestfailedid = null;

        if (!empty($events)) {   // do nothing if there are no events to push
            $HttpSocket = new HttpSocket();

            $this->loadModel('Attribute');
            // upload each event separately and keep the results in the $successes and $fails arrays
            foreach ($events as $event) {
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
            if (sizeof($fails) > 0) {
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
