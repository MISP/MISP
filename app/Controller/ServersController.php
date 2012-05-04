<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

/**
 * Servers Controller
 *
 * @property Server $Server
 */
class ServersController extends AppController {

    public $components = array('Security' ,'RequestHandler');
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

        // permit reuse of CSRF tokens on the search page.
        if ('sync' == $this->request->params['action']) {
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

        $this->Server->read(null, $id);

        if ("full"==$full) {
            // pull everything
            // TODO make the output of the sync functionality more user-friendly
            $this->_import($this->Server->data['Server']['url'], $this->Server->data['Server']['authkey']);
        } else {
            // TODO incremental pull
            // lastpulledid
            throw new NotFoundException('Sorry, this is not yet implemented');

            // increment lastid based on the highest ID seen
        }
    }


    public function push($id = null, $full=false) {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->Server->id = $id;
        if (!$this->Server->exists()) {
            throw new NotFoundException(__('Invalid server'));
        }

        App::import('Controller', 'Events');
        App::uses('HttpSocket', 'Network/Http');

        $this->Server->read(null, $id);

        if ("full"==$full) {
            $lastpushedid = 0;

        } else {
            $lastpushedid = $this->Server->data['Server']['lastpushedid'];
        }
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
// FIXME file attachments are not synced
        $successes = array();
        $fails = array();

        $HttpSocket = new HttpSocket();
        $uri = $this->Server->data['Server']['url'].'/events';
        $request = array(
                'header' => array(
                        'Authorization' => $this->Server->data['Server']['authkey'],
                        'Accept' => 'application/xml',
                        'Content-Type' => 'application/xml',
                        //'Connection' => 'keep-alive' // LATER followup cakephp ticket 2854 about this problem http://cakephp.lighthouseapp.com/projects/42648-cakephp/tickets/2854
                )
        );


        foreach ($events as $event) {
                // TODO try to do this using a separate EventsController
//                 $eventsController = new EventsController();
//                 $this->RequestHandler->renderAs($eventsController, 'xml');
//                 debug($eventsController);
//                 $eventsController->set('event', $event);
//                 $eventsController->set('isAdmin', $this->_isAdmin());
//                 $view = new View($eventsController);
//                 $viewdata = $view->render('view');
//                 print $viewdata;

//                 // get the output in Xml
//                 $this->RequestHandler->renderAs($this, 'xml');
//                 $this->viewPath = 'Events';
//                 $this->set('event', $event);
//                 $this->set('isAdmin', $this->_isAdmin());
//                 $eventsXml = $this->render('view');

            $xmlArray = array();
            // rearrange things to be compatible with the Xml::fromArray()
            $event['Event']['Attribute'] = $event['Attribute'];
            unset($event['Attribute']);

            // cleanup the array from things we do not want to expose
            unset($event['Event']['user_id']);
            unset($event['Event']['org']);
            // remove value1 and value2 from the output
            foreach($event['Event']['Attribute'] as $key => $value) {
                unset($event['Event']['Attribute'][$key]['value1']);
                unset($event['Event']['Attribute'][$key]['value2']);
                // do not keep attributes that are private
                if ($event['Event']['Attribute'][$key]['private']) {
                    unset($event['Event']['Attribute'][$key]);
                }
            }

            // display the XML to the user
            $xmlArray['Event'][] = $event['Event'];
            $xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
            $eventsXml = $xmlObject->asXML();
            // do a REST POST request with the server
            $data = $eventsXml;
            // LATER validate HTTPS SSL certificate
            $response = $HttpSocket->post($uri, $data, $request);
            if ($response->isOk()) {
                $successes[] = $event['Event']['id'];
            }
            else {
                $fails[$event['Event']['id']] = $response->body;
            }
            $lastpushedid = max($lastpushedid, $event['Event']['id']);
        }

        $this->set('successes', $successes);
        $this->set('fails', $fails);
        // increment lastid based on the highest ID seen
        $this->Server->saveField('lastpushedid', $lastpushedid);
    }

    private function _testXmlArrayProblem() {
        $xmlArray = array(
                'Event' => array(
                        (int) 0 => array(
                                'id' => '235',
                                'Attribute' => array(
                                        (int) 0 => array(
                                                'id' => '9646',
                                        ),
                                        (int) 2 => array(
                                                'id' => '9647',
                                        )
                                )
                        )
                )
        );
        $xmlObject = Xml::fromArray($xmlArray);
        debug($xmlObject->asXML());

        exit();
    }


	private function _import($url, $key, $eventid=null) {
	    $this->response->type('txt');    // set the content type
	    $this->header('Content-Disposition: inline; filename="import.txt"');
	    $this->layout = 'text/default';

        if(null != $eventid) {
            $xmlurl = $url."/events/xml/".$key."/".$eventid;
        } else {
            $xmlurl = $url."/events/xml/".$key;
        }

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
                //print 'Event '. $eventArray['event']['uuid'].' doesn\'t exist yet.'."\n";

                $this->Event->create();
                $this->Event->data['Event'] = $eventArray['event'];
                unset($this->Event->data['Event']['id']);
                unset($this->Event->data['Event']['attribute']);
                if (empty($this->Event->data['Event']['info']))
                    $this->Event->data['Event']['info'] = '-';

                // force check userid and orgname to be from yourself
                $this->Event->data['Event']['user_id'] = 0;
                $this->Event->data['Event']['org'] = 'imported';
                $this->Event->data['Event']['private'] = true;

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
            // FIXME also import the file-attachments
        }

	}
}
