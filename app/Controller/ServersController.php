<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

/**
 * Servers Controller
 *
 * @property Server $Server
 */
class ServersController extends AppController {


    function beforeFilter() {
        parent::beforeFilter();

        // These variables are required for every view
        $this->set('me', $this->Auth->user());
        $this->set('isAdmin', $this->_isAdmin());
    }

    public function isAuthorized($user) {
        // Admins can access everything
        if (parent::isAuthorized($user)) {
            return true;
        }
//         // Only on own events for these actions
//         if (in_array($this->action, array('edit', 'delete', 'alert'))) {
//             $eventid = $this->request->params['pass'][0];
//             return $this->Event->isOwnedByOrg($eventid, $this->Auth->user('org'));
//         }
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
		$this->set('servers', $this->paginate());
	}

/**
 * view method
 *
 * @param string $id
 * @return void
 */
	public function view($id = null) {
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		$this->set('server', $this->Server->read(null, $id));
	}

/**
 * add method
 *
 * @return void
 */
	public function add() {
		if ($this->request->is('post')) {
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
		if ($this->request->is('post') || $this->request->is('put')) {
			if ($this->Server->save($this->request->data)) {
				$this->Session->setFlash(__('The server has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The server could not be saved. Please, try again.'));
			}
		} else {
			$this->request->data = $this->Server->read(null, $id);
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


	public function import($server, $key, $eventid=null) {
	    $this->response->type('txt');    // set the content type
	    $this->header('Content-Disposition: inline; filename="import.txt"');
	    $this->layout = 'text/default';

	    $url = 'https://'.$server;
        if(null != $eventid) {
            $xmlurl = $url."/events/xml/".$key."/".$eventid;
        } else {
            $xmlurl = $url."/events/xml/".$key;
        }

//         $xmlurl = APP.DS."files".DS."157.xml";
//         $xmlurl = APP.DS."files".DS."all.xml";
//         $xmlurl = APP.DS."files".DS."163.xml"; // unexisting

        print 'Importing data from '.$xmlurl."\n";
        $this->loadModel('Event');
        $this->loadModel('Attribute');
        $xml = Xml::build($xmlurl);

        foreach ($xml as $eventElement) {
            $eventArray = Xml::toArray($eventElement);
            // check if the event already exists :
            // if it doesn't => create the event and all the signatures
            $params = array(
                    'conditions' => array('Event.uuid' => $eventArray['event']['uuid']),
                    'recursive' => 0,
                    'fields' => array('Event.id'),
            );
            $db_event = $this->Event->find('first', $params);

            if ($db_event) {
                print 'Event '. $eventArray['event']['uuid'].' already exists.'."\n";
                // FIXME if event it exists, iterate over the attributes and import the new ones

            } else {
                // create a new event
                print 'Event '. $eventArray['event']['uuid'].' doesn\'t exist yet.'."\n";

                $this->Event->create();
                $this->Event->data['Event'] = $eventArray['event'];
                unset($this->Event->data['Event']['id']);
                unset($this->Event->data['Event']['attribute']);
                if (empty($this->Event->data['Event']['info']))
                    $this->Event->data['Event']['info'] = '-';

                // force check userid and orgname to be from yourself
                $this->Event->data['Event']['user_id'] = 0; // FIXME do this another way because it will cause problems with automation
                $this->Event->data['Event']['org'] = 'imported'; // FIXME do this another way because it will cause problems with automation

                if ($this->Event->save($this->Event->data)) {
                    print 'Event '.$eventArray['event']['uuid'].' saved'."\n";
                } else {
                    debug($eventArray['event']);
                    debug($this->Event->validationErrors);
                    print 'ERROR Event NOT saved: '.$eventArray['event']['uuid']."\n";
                    // ignore this event and continue to the next one
                    continue;
                }

                // when an event has only one attribute, the $eventArray['event']['attribute']
                // is not an array containing the Attribute values, so we need a little workaround
                if (isset($eventArray['event']['attribute']['id'])) {
                    $attribute = $eventArray['event']['attribute'];
                    unset($eventArray['event']['attribute']);
                    $eventArray['event']['attribute'] = array($attribute);
                }

                // iterate over the array containing attributes
                // LATER change to saveMany()
                foreach ($eventArray['event']['attribute'] as $id => $attribute) {
                    $this->Attribute->create();
                    $this->Attribute->data['Attribute'] = $attribute;
                    unset($this->Attribute->data['Attribute']['id']);
                    $this->Attribute->data['Attribute']['event_id'] = $this->Event->id;

                    if ($this->Attribute->save($this->Attribute->data)) {
                        print 'Event '.$eventArray['event']['uuid'].' Attribute saved: '.$eventArray['event']['attribute'][$id]['uuid']."\n";
                    } else {
                        debug($attribute);
                        debug($this->Attribute->validationErrors);
                        print 'ERROR Event '.$eventArray['event']['uuid'].' Attribute NOT saved: '.$eventArray['event']['attribute'][$id]['uuid']."\n";
                    }

                }


            }

            // TODO check if we want to send out email to alert that there is a new event
        }

	}
}
