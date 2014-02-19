<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');
/**
 * Events Controller
 *
 * @property Event $Event
*/
class EventsController extends AppController {

	/**
	 * Components
	 *
	 * @var array
	 */
	public $components = array(
			'Security',
			'Email',
			'RequestHandler',
			'IOCExport',
			'IOCImport',
			'Cidr'
	);

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'Event.timestamp' => 'DESC'
			),
	);

	public $helpers = array('Js' => array('Jquery'));

	public function beforeFilter() {
		parent::beforeFilter();

		// what pages are allowed for non-logged-in users
		$this->Auth->allow('xml');
		$this->Auth->allow('nids');
		$this->Auth->allow('hids_md5');
		$this->Auth->allow('hids_sha1');
		$this->Auth->allow('text');
		$this->Auth->allow('dot');
		$this->Auth->allow('restSearch');

		// TODO Audit, activate logable in a Controller
		if (count($this->uses) && $this->{$this->modelClass}->Behaviors->attached('SysLogLogable')) {
			$this->{$this->modelClass}->setUserData($this->activeUser);
		}

		// convert uuid to id if present in the url, and overwrite id field
		if (isset($this->params->query['uuid'])) {
			$params = array(
					'conditions' => array('Event.uuid' => $this->params->query['uuid']),
					'recursive' => 0,
					'fields' => 'Event.id'
			);
			$result = $this->Event->find('first', $params);
			if (isset($result['Event']) && isset($result['Event']['id'])) {
				$id = $result['Event']['id'];
				$this->params->addParams(array('pass' => array($id))); // FIXME find better way to change id variable if uuid is found. params->url and params->here is not modified accordingly now
			}
		}

		// if not admin or own org, check private as well..
		if (!$this->_isSiteAdmin()) {
			$this->paginate = Set::merge($this->paginate,array(
					'conditions' =>
					array("OR" => array(
							array('Event.org =' => $this->Auth->user('org')),
							array('Event.distribution >' => 0),
			))));
		}
	}

	/**
	 * index method
	 *
	 * @return void
	 */
	public function index() {
        /*$alertUsers = $this->Event->User->find('all', array(

                    'contain' => array('Organisation' => array(
                        'SharingGroup' => array(
                        'conditions' => array('SharingGroup.id' => 2)))),
                    'recursive' => -1,
            ));

        //$this->S = ClassRegistry::init('SharingGroup');
        //$u = $this->S->find('all', array('contain' => array('Organisation' => array('User'))));
        die(debug($alertUsers));*/
		// list the events

		// TODO information exposure vulnerability - as we don't limit the filter depending on the MISP.showorg parameter
		// this filter will work if showorg=false and users will be able to perform the filtering and see what events were posted by what org.
		// same goes for orgc in all cases
		//transform POST into GET
		if($this->request->is("post")) {
			$url = array('action'=>'index');
			$filters = array();
			if (isset($this->data['Event'])) {
				$filters = $this->data['Event'];
			}

			//redirect user to the index page including the selected filters
			$this->redirect(array_merge($url,$filters));
		}
		if (Configure::read('MISP.tagging') && !$this->_isRest()) {
			$this->Event->contain(array('User.email', 'EventTag' => array('Tag')));
			$tags = $this->Event->EventTag->Tag->find('all', array('recursive' => -1));
			$tagNames = array('None');
			foreach ($tags as $k => $v) {
				$tagNames[$v['Tag']['id']] = $v['Tag']['name'];
			}
			$this->set('tags', $tagNames);
		} else {
			$this->Event->contain('User.email');
		}
		// check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
		foreach ($this->passedArgs as $k => $v) {
			if (substr($k, 0, 6) === 'search') {
				$searchTerm = substr($k, 6);
				switch ($searchTerm) {
					case 'published' :
						if ($v == 2) continue 2;
						else $this->paginate['conditions'][] = array('Event.' . substr($k, 6) . ' =' => $v);
						break;
					case 'Datefrom' :
						if (!$v) continue 2;
						$this->paginate['conditions'][] = array('Event.date >=' => $v);
						break;
					case 'Dateuntil' :
						if (!$v) continue 2;
						$this->paginate['conditions'][] = array('Event.date <=' => $v);
						break;
					case 'org' :
						if (!$v) continue 2;
						// if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
						$pieces = explode('|', $v);
						$test = array();
						foreach ($pieces as $piece) {
							if ($piece[0] == '!') {
								$this->paginate['conditions']['AND'][] = array('Event.orgc' . ' NOT LIKE' => '%' . substr($piece, 1) . '%');
							} else {
								$test['OR'][] = array('Event.orgc' . ' LIKE' => '%' . $piece . '%');
							}
						}
						$this->paginate['conditions']['AND'][] = $test;
						break;
					case 'info' :
						if (!$v) continue 2;
						// if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
						$pieces = explode('|', $v);
						$test = array();
						foreach ($pieces as $piece) {
							if ($piece[0] == '!') {
								$this->paginate['conditions']['AND'][] = array('Event.info' . ' NOT LIKE' => '%' . substr($piece, 1) . '%');
							} else {
								$test['OR'][] = array('Event.info' . ' LIKE' => '%' . $piece . '%');
							}
						}
						$this->paginate['conditions']['AND'][] = $test;
						break;
					case 'tag' :
						if (!$v || !Configure::read('MISP.tagging') || $v == 0) continue 2;
						$valid = $this->Event->EventTag->find('all', array(
								'conditions' => array('tag_id' => $v),
								'fields' => 'event_id',
								'recursive' => -1,
						));
						if (empty($valid)) {
							$this->paginate['conditions']['AND'][] = array('Event.id' => '-1');
						}
						$test = array();
						//$valid = array_unique($valid);
						foreach ($valid as $et) {
							$test['OR'][] = array('Event.id' => $et['EventTag']['event_id']);
						}
						$this->paginate['conditions']['AND'][] = $test;
						break;
					default:
						if (!$v) continue 2;
						$this->paginate['conditions'][] = array('Event.' . substr($k, 6) . ' LIKE' => '%' . $v . '%');
						break;
				}
			}
		}
        if (!$this->_IsSiteAdmin()) {
            $org = $this->Event->User->Organisation->read(null, $this->Auth->user('organisation_id'));
            $this->paginate['group'] = 'Event.id';
            $this->paginate['joins'] = array(
                array(
                    'table' => 'events_sharing_groups',
                    'alias' => 'EventsSharingGroup',
                    'type' => 'inner',
                    'conditions'=> array('EventsSharingGroup.event_id = Event.id')
                ),
                array(
                    'table' => 'sharing_groups',
                    'alias' => 'SharingGroup',
                    'type' => 'inner',
                    'conditions'=> array(
                        'SharingGroup.id = EventsSharingGroup.sharing_group_id',
                        'SharingGroup.id' => Set::extract('/SharingGroup/id', $org)
                        )
                )
            );
        }

		$this->paginate = Set::merge($this->paginate, array('contain' => array(
			'ThreatLevel' => array(
				'fields' => array(
					'ThreatLevel.name'))
		)));
		$this->set('events', $this->paginate());
		if (!$this->Auth->user('gpgkey')) {
			$this->Session->setFlash(__('No GPG key set in your profile. To receive emails, submit your public key in your profile.'));
		}
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
		$this->set('distributionLevels', $this->Event->distributionLevels);
	}


	/**
	 * view method
	 *
	 * @param int $id
	 * @return void
	 * @throws NotFoundException
	 */

	public function view($id = null, $continue=false, $fromEvent=null) {
		// If the length of the id provided is 36 then it is most likely a Uuid - find the id of the event, change $id to it and proceed to read the event as if the ID was entered.
		$perm_publish = $this->userRole['perm_publish'];
		if (strlen($id) == 36) {
			$this->Event->recursive = -1;
			$temp = $this->Event->findByUuid($id);
			if ($temp == null) throw new NotFoundException(__('Invalid event'));
			$id = $temp['Event']['id'];
		}
		$isSiteAdmin = $this->_isSiteAdmin();

		$this->Event->id = $id;
		if(!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event.'));
		}
		$results = $this->__fetchEvent($id);
		if ($this->_isRest()) {
			$this->loadModel('Attribute');
			foreach ($results[0]['Attribute'] as &$attribute) {
				if ($this->Attribute->typeIsAttachment($attribute['type'])) {
					$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
					$attribute['data'] = $encodedFile;
				}
			}
		}

		$this->loadModel('Log');
		$logEntries = $this->Log->find('all', array(
			'conditions' => array('title LIKE' => '%Event (' . $id . ')%', 'org !=' => $results[0]['Event']['orgc']),
			'fields' => array('org'),
			'group' => 'org'
		));
		foreach ($logEntries as $k => $entry) {
			if (!isset($entry['Log']['org'])) unset ($logEntries[$k]);
		}
		$this->set('logEntries', $logEntries);
		// This happens if the user doesn't have permission to view the event.
		// TODO change this to NotFoundException to keep it in line with the other invalid event messages, but will have to check if it impacts the sync before doing that
		if (!isset($results[0])) {
			$this->Session->setFlash(__('Invalid event.'));
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		}
		// We'll only have one event in the array since we specified an id. The array returned only has several elements in the xml exports
		$result = $results[0];
		$this->loadModel('Attribute');

		$this->set('authkey', $this->Auth->user('authkey'));
		$this->set('baseurl', Configure::read('MISP.baseurl'));

		$this->set('relatedAttributes', $result['RelatedAttribute']);
		// passing decriptions for model fields
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);
		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('event', $result);
		if(isset($result['ShadowAttribute'])) {
			$this->set('remaining', $result['ShadowAttribute']);
		}
		$this->set('relatedEvents', $result['RelatedEvent']);

		$this->set('categories', $this->Attribute->validate['category']['rule'][1]);

		// passing type and category definitions (explanations)
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);

		// combobox for analysis
		$this->set('distributionDescriptions', $this->Event->distributionDescriptions);
		$this->set('distributionLevels', $this->Event->distributionLevels);

		// combobox for analysis
		$analysiss = $this->Event->validate['analysis']['rule'][1];
		$analysiss = $this->_arrayToValuesIndexArray($analysiss);
		$this->set('analysiss', $analysiss);
		// tooltip for analysis
		$this->set('analysisDescriptions', $this->Event->analysisDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
		if (!$this->_isRest()) {
			$this->helpers[] = 'Pivot';
			if ($continue) {
				$data = $this->__continuePivoting($result['Event']['id'], $result['Event']['info'], $result['Event']['date'], $fromEvent);
			} else {
				$data = $this->__startPivoting($result['Event']['id'], $result['Event']['info'], $result['Event']['date']);
			}
			$this->set('allPivots', $this->Session->read('pivot_thread'));
			$pivot = $this->Session->read('pivot_thread');
			$this->__arrangePivotVertical($pivot);
			$this->__setDeletable($pivot, $id, true);
			$this->set('pivot', $pivot);
			$this->set('currentEvent', $id);

			$this->set('allPivots', $this->Session->read('pivot_thread'));
			// Show the discussion
			$this->loadModel('Thread');
			$params = array('conditions' => array('event_id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'event_id', 'distribution', 'title')
			);
			$thread = $this->Thread->find('first', $params);
			if (empty($thread)) {
				$newThread = array(
						'date_created' => date('Y/m/d H:i:s'),
						'date_modified' => date('Y/m/d H:i:s'),
						'user_id' => $this->Auth->user('id'),
						'event_id' => $id,
						'title' => 'Discussion about Event #' . $result['Event']['id'] . ' (' . $result['Event']['info'] . ')',
						'distribution' => $result['Event']['distribution'],
						'post_count' => 0,
						'org' => $result['Event']['orgc']
				);
				$this->Thread->save($newThread);
				$thread = ($this->Thread->read());
			} else {
				if ($thread['Thread']['distribution'] != $result['Event']['distribution']) {
					$this->Thread->saveField('distribution', $result['Event']['distribution']);
				}
			}
			$this->loadModel('Post');
			$this->paginate['Post'] = array(
					'limit' => 5,
					'conditions' => array('Post.thread_id' => $thread['Thread']['id']),
					'contain' => 'User'
			);
			$posts = $this->paginate('Post');
			// Show the discussion
			$this->set('posts', $posts);
			$this->set('thread_id', $thread['Thread']['id']);
			$this->set('myuserid', $this->Auth->user('id'));
			$this->set('thread_title', $thread['Thread']['title']);
			if ($this->request->is('ajax')) {
				$this->disableCache();
				$this->layout = 'ajax';
				$this->render('/Elements/eventdiscussion');
			}
			$pivot = $this->Session->read('pivot_thread');
			$this->__arrangePivotVertical($pivot);
			$this->__setDeletable($pivot, $id, true);
			$this->set('pivot', $pivot);
			if (Configure::read('MISP.tagging')) {
				$this->helpers[] = 'TextColour';
				$this->loadModel('EventTag');
				$tags = $this->EventTag->find('all', array(
						'conditions' => array(
								'event_id' => $id
						),
						'contain' => 'Tag',
						'fields' => array('Tag.id', 'Tag.colour', 'Tag.name'),
						));
				$this->set('tags', $tags);
				$tags = $this->Event->EventTag->Tag->find('all', array('recursive' => -1));
				$tagNames = array('None');
				foreach ($tags as $k => $v) {
					$tagNames[$v['Tag']['id']] = $v['Tag']['name'];
				}
				$this->set('allTags', $tagNames);

			}
		}
		$this->set('currentEvent', $id);
	}

	private function __startPivoting($id, $info, $date){
		$this->Session->write('pivot_thread', null);
		$initial_pivot = array('id' => $id, 'info' => $info, 'date' => $date, 'depth' => 0, 'height' => 0, 'children' => array(), 'deletable' => true);
		$this->Session->write('pivot_thread', $initial_pivot);
	}

	private function __continuePivoting($id, $info, $date, $fromEvent){
		$pivot = $this->Session->read('pivot_thread');
		$newPivot = array('id' => $id, 'info' => $info, 'date' => $date, 'depth' => null, 'children' => array(), 'deletable' => true);
		if (!$this->__checkForPivot($pivot, $id)) {
			$pivot = $this->__insertPivot($pivot, $fromEvent, $newPivot, 0);
		}
		$this->Session->write('pivot_thread', $pivot);
	}

	private function __insertPivot($pivot, $oldId, $newPivot, $depth) {
		$depth++;
		if ($pivot['id'] == $oldId) {
			$newPivot['depth'] = $depth;
			$pivot['children'][] = $newPivot;
			return $pivot;
		}
		foreach($pivot['children'] as $k => $v) {
			$pivot['children'][$k] = $this->__insertPivot($v, $oldId, $newPivot, $depth);
		}
		return $pivot;
	}

	private function __checkForPivot($pivot, $id) {
		if ($id == $pivot['id']) return true;
		foreach ($pivot['children'] as $k => $v) {
			if ($this->__checkForPivot($v, $id)) {
				return true;
			}
		}
		return false;
	}

	private function __arrangePivotVertical(&$pivot) {
		if (empty($pivot)) return null;
		$max = count($pivot['children']) - 1;
		if ($max < 0) $max = 0;
		$temp = 0;
		$pivot['children'] = array_values($pivot['children']);
		foreach ($pivot['children'] as $k => $v) {
			$pivot['children'][$k]['height'] = ($temp+$k)*50;
			$temp += $this->__arrangePivotVertical($pivot['children'][$k]);
			if ($k == $max) $temp = $pivot['children'][$k]['height'] / 50;
		}
		return $temp;
	}

	public function removePivot($id, $eventId, $self = false) {
		$pivot = $this->Session->read('pivot_thread');
		if ($pivot['id'] == $id) {
			$pivot = null;
			$this->Session->write('pivot_thread', null);
			$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
		} else {
			$pivot = $this->__doRemove($pivot, $id);
		}
		$this->Session->write('pivot_thread', $pivot);
		$pivot = $this->__arrangePivotVertical($pivot);
		$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId, true, $eventId));
	}

	private function __removeChildren(&$pivot, $id) {
		if ($pivot['id'] == $id) {
			$pivot['children'] = array();
		} else {
			foreach ($pivot['children'] as $k => $v) {
				$this->__removeChildren($v, $id);
			}
		}
	}

	private function __doRemove(&$pivot, $id) {
		foreach ($pivot['children'] as $k => $v) {
			if ($v['id'] == $id) {
				unset ($pivot['children'][$k]);
				return $pivot;
			} else {
				$pivot['children'][$k] = $this->__doRemove($pivot['children'][$k], $id);
			}
		}
		return $pivot;
	}

	private function __setDeletable(&$pivot, $id, $root=false) {
		if ($pivot['id'] == $id && !$root) {
			$pivot['deletable'] = false;
			return true;
		}
		$containsCurrent = false;
		foreach ($pivot['children'] as $k => $v) {
			$containsCurrent = $this->__setDeletable($pivot['children'][$k], $id);
			if ($containsCurrent && !$root) $pivot['deletable'] = false;
		}
		return !$pivot['deletable'];
	}

	/**
	 * add method
	 *
	 * @return void
	 */
	public function add() {
		if ($this->request->is('post')) {
			if ($this->_isRest()) {
				// Distribution, reporter for the events pushed will be the owner of the authentication key
				$this->request->data['Event']['user_id'] = $this->Auth->user('id');
			}
			if (!empty($this->data)) {
				$ext = '';
				if (isset($this->data['Event']['submittedgfi'])) {
					App::uses('File', 'Utility');
					$file = new File($this->data['Event']['submittedgfi']['name']);
					$ext = $file->ext();
				}
				if (isset($this->data['Event']['submittedgfi']) && ($ext != 'zip') && $this->data['Event']['submittedgfi']['size'] > 0 &&
						is_uploaded_file($this->data['Event']['submittedgfi']['tmp_name'])) {
					$this->Session->setFlash(__('You may only upload GFI Sandbox zip files.'));
				} else {
					if ($this->_isRest()) $this->request->data = $this->updateXMLArray($this->request->data, false);
					$add = $this->Event->_add($this->request->data, $this->_isRest(), $this->Auth->user(), '');
					if ($add && !is_numeric($add)) {
						if ($this->_isRest()) {
							// REST users want to see the newly created event
							$this->view($this->Event->getId());
							$this->render('view');
						} else {
							// TODO now save uploaded attributes using $this->Event->getId() ..
							if (isset($this->data['Event']['submittedgfi'])) $this->_addGfiZip($this->Event->getId());

							// redirect to the view of the newly created event
							if (!CakeSession::read('Message.flash')) {
								$this->Session->setFlash(__('The event has been saved'));
							} else {
								$existingFlash = CakeSession::read('Message.flash');
								$this->Session->setFlash(__('The event has been saved. ' . $existingFlash['message']));
							}
							$this->redirect(array('action' => 'view', $this->Event->getId()));
						}
					} else {
						if ($this->_isRest()) { // TODO return error if REST
							if(is_numeric($add)) {
								$this->response->header('Location', Configure::read('MISP.baseurl') . '/events/' . $add);
								$this->response->send();
							}
							// REST users want to see the failed event
							$this->view($this->Event->getId());
							$this->render('view');
						} else {
							$this->Session->setFlash(__('The event could not be saved. Please, try again.'), 'default', array(), 'error');
							// TODO return error if REST
						}
					}
				}
			}
		}

		// combobox for distribution
		$distributions = array_keys($this->Event->distributionDescriptions);
		$distributions = $this->_arrayToValuesIndexArray($distributions);
		$this->set('distributions', $distributions);
		// tooltip for distribution
		$this->set('distributionDescriptions', $this->Event->distributionDescriptions);
		$this->set('distributionLevels', $this->Event->distributionLevels);

		// combobox for risks
		$threat_levels = $this->Event->ThreatLevel->find('all');
		$this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
		$this->set('riskDescriptions', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.form_description'));

		// combobox for analysis
		$analysiss = $this->Event->validate['analysis']['rule'][1];
		$analysiss = $this->_arrayToValuesIndexArray($analysiss);
		$this->set('analysiss',$analysiss);
		// tooltip for analysis
		$this->set('analysisDescriptions', $this->Event->analysisDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
		$this->set('sharingGroups', $this->Event->SharingGroup->find('list'));
        $org = $this->Event->User->Organisation->read(null, $this->Auth->user('organisation_id'));
        $this->set('selectedSharingGroups', Set::extract('/SharingGroup/id', $org));

        $this->set('servers', $this->Event->Server->find('list'));
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);
	}

	public function addIOC($id) {
		$this->Event->recursive = -1;
		$this->Event->read(null, $id);
		if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
			throw new UnauthorizedException('You do not have permission to do that.');
		}
		if ($this->request->is('post')) {
			if (!empty($this->data)) {
				$ext = '';
				if (isset($this->data['Event']['submittedioc'])) {
					App::uses('File', 'Utility');
					$file = new File($this->data['Event']['submittedioc']['name']);
					$ext = $file->ext();
				}
				if (isset($this->data['Event']['submittedioc']) && ($ext != 'ioc') && $this->data['Event']['submittedioc']['size'] > 0 &&
						is_uploaded_file($this->data['Event']['submittedioc']['tmp_name'])) {
					$this->Session->setFlash(__('You may only upload OpenIOC ioc files.'));
				}
				if (isset($this->data['Event']['submittedioc'])) $this->_addIOCFile($id);

				// redirect to the view of the newly created event
				if (!CakeSession::read('Message.flash')) {
					$this->Session->setFlash(__('The event has been saved'));
				} else {
					$existingFlash = CakeSession::read('Message.flash');
					$this->Session->setFlash(__('The event has been saved. ' . $existingFlash['message']));
				}
			}
		}
		// set the id
		$this->set('id', $id);
		// set whether it is published or not
		$this->set('published', $this->Event->data['Event']['published']);
	}

	public function add_xml() {
		if (!$this->userRole['perm_modify']) {
			throw new UnauthorizedException('You do not have permission to do that.');
		}
		if ($this->request->is('post')) {
			if (!empty($this->data)) {
				$ext = '';
				if (isset($this->data['Event']['submittedxml'])) {
					App::uses('File', 'Utility');
					$file = new File($this->data['Event']['submittedxml']['name']);
					$ext = $file->ext();
				}
				if (isset($this->data['Event']['submittedxml']) && ($ext != 'xml') && $this->data['Event']['submittedxml']['size'] > 0 &&
				is_uploaded_file($this->data['Event']['submittedxml']['tmp_name'])) {
					$this->Session->setFlash(__('You may only upload MISP XML files.'));
				}
				if (isset($this->data['Event']['submittedxml'])) $this->_addXMLFile();

				// redirect to the view of the newly created event
				if (!CakeSession::read('Message.flash')) {
					$this->Session->setFlash(__('The event has been saved'));
				} else {
					$existingFlash = CakeSession::read('Message.flash');
					$this->Session->setFlash(__('The event has been saved. ' . $existingFlash['message']));
				}
			}
		}
	}


	/**
	 * Low level function to add an Event based on an Event $data array
	 *
	 * @return bool true if success
	 */
	public function _add(&$data, $fromXml, $or='', $passAlong = null, $fromPull = false) {
		$this->Event->create();
		// force check userid and orgname to be from yourself
		$auth = $this->Auth;
		$data['Event']['user_id'] = $auth->user('id');
		$date = new DateTime();

		//if ($this->checkAction('perm_sync')) $data['Event']['org'] = Configure::read('MISP.org');
		//else $data['Event']['org'] = $auth->user('org');
		$data['Event']['org'] = $auth->user('org');
		// set these fields if the event is freshly created and not pushed from another instance.
		// Moved out of if (!$fromXML), since we might get a restful event without the orgc/timestamp set
		if (!isset ($data['Event']['orgc'])) $data['Event']['orgc'] = $data['Event']['org'];
		if ($fromXml) {
			// Workaround for different structure in XML/array than what CakePHP expects
			$this->Event->cleanupEventArrayFromXML($data);
			// the event_id field is not set (normal) so make sure no validation errors are thrown
			// LATER do this with	 $this->validator()->remove('event_id');
			unset($this->Event->Attribute->validate['event_id']);
			unset($this->Event->Attribute->validate['value']['unique']); // otherwise gives bugs because event_id is not set
		}

		unset ($data['Event']['id']);
		if (isset($data['Event']['uuid'])) {
			// check if the uuid already exists
			$existingEventCount = $this->Event->find('count', array('conditions' => array('Event.uuid' => $data['Event']['uuid'])));
			if ($existingEventCount > 0) {
				// RESTfull, set responce location header..so client can find right URL to edit
				if ($fromPull) return false;
				$existingEvent = $this->Event->find('first', array('conditions' => array('Event.uuid' => $data['Event']['uuid'])));
				$this->response->header('Location', Configure::read('MISP.baseurl') . '/events/' . $existingEvent['Event']['id']);
                // If event is found send 302 Found instead of 404 Not Found
                $this->response->statusCode(302);
				$this->response->header('Location', Configure::read('CyDefSIG.baseurl') . '/events/' . $existingEvent['Event']['id']);
				$this->response->send();
				return false;
			}
		}
		if (isset($data['Attribute'])) {
			foreach ($data['Attribute'] as &$attribute) {
				unset ($attribute['id']);
			}
		}
		// FIXME chri: validatebut  the necessity for all these fields...impact on security !
		$fieldList = array(
				'Event' => array('org', 'orgc', 'date', 'threat_level_id', 'analysis', 'info', 'user_id', 'published', 'uuid', 'timestamp', 'distribution', 'locked'),
				'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'revision', 'timestamp', 'distribution')
		);

		$saveResult = $this->Event->saveAssociated($data, array('validate' => true, 'fieldList' => $fieldList,
			'atomic' => false));

		// FIXME chri: check if output of $saveResult is what we expect when data not valid, see issue #104
		if ($saveResult) {
            if(!empty($data['Event']['SharingGroup'])){
                foreach($data['Event']['SharingGroup'] as $dsg){
                    if($this->Event->SharingGroup->exists($dsg['id'])){
                        $sg = array();
                        $sg['sharing_group_id'] = $dsg['id'];
                        $sg['event_id'] = $this->Event->getId();
                        $this->Event->EventsSharingGroup->create();
                        $this->Event->EventsSharingGroup->save($sg);
                    }
                }
            }
			if (!empty($data['Event']['published']) && 1 == $data['Event']['published']) {
				// do the necessary actions to publish the event (email, upload,...)
				if ('true' != Configure::read('MISP.disablerestalert')) {
					$this->Event->sendAlertEmailRouter($this->Event->getId(), $this->Auth->user(), $this->_isSiteAdmin());
				}
				$this->Event->publish($this->Event->getId(), $passAlong);
			}
			return true;
		} else {
			//throw new MethodNotAllowedException("Validation ERROR: \n".var_export($this->Event->validationErrors, true));
			return false;
		}
	}

	public function _edit(&$data, $id) {
		$this->Event->read(null, $id);
		if (!isset ($data['Event']['orgc'])) $data['Event']['orgc'] = $data['Event']['org'];
		if ($this->Event->data['Event']['timestamp'] < $data['Event']['timestamp']) {

		} else {
			return 'Event exists and is the same or newer.';
		}
		if (!$this->Event->data['Event']['locked']) {
			return 'Event originated on this instance, any changes to it have to be done locally.';
		}
		$fieldList = array(
				'Event' => array('date', 'threat_level_id', 'analysis', 'info', 'published', 'uuid', 'from', 'distribution', 'timestamp'),
				'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'revision', 'distribution', 'timestamp')
		);
		$data['Event']['id'] = $this->Event->data['Event']['id'];
		if (isset($data['Event']['Attribute'])) {
			foreach ($data['Event']['Attribute'] as $k => &$attribute) {
				$existingAttribute = $this->__searchUuidInAttributeArray($attribute['uuid'], $this->Event->data);
				if (count($existingAttribute)) {
					$data['Event']['Attribute'][$k]['id'] = $existingAttribute['Attribute']['id'];
					// Check if the attribute's timestamp is bigger than the one that already exists.
					// If yes, it means that it's newer, so insert it. If no, it means that it's the same attribute or older - don't insert it, insert the old attribute.
					// Alternatively, we could unset this attribute from the request, but that could lead with issues if we decide that we want to start deleting attributes that don't exist in a pushed event.
					if ($data['Event']['Attribute'][$k]['timestamp'] > $existingAttribute['Attribute']['timestamp']) {

					} else {
						unset($data['Event']['Attribute'][$k]);
					}
				} else {
					unset($data['Event']['Attribute'][$k]['id']);
				}
			}
		}
		$this->Event->cleanupEventArrayFromXML($data);
		$saveResult = $this->Event->saveAssociated($data, array('validate' => true, 'fieldList' => $fieldList));
		if ($saveResult) return 'success';
		else return 'Saving the event has failed.';
	}

	private function __searchUuidInAttributeArray($uuid, &$attr_array) {
		foreach ($attr_array['Attribute'] as &$attr) {
			if ($attr['uuid'] == $uuid)	return array('Attribute' => $attr);
		}
		return false;
	}

	/**
	 * edit method
	 *
	 * @param int $id
	 * @return void
	 * @throws NotFoundException
	 */
	public function edit($id = null) {
		$this->Event->id = $id;
		$date = new DateTime();
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}

        if(!$this->_isSiteAdmin() && !$this->_isInMySharingGroup($id)){
            $this->Session->setFlash(__('This event is not part of your sharing group, you are not authorized to view it.'));
            $this->redirect(array('controller' => 'events', 'action' => 'index'));
        }

		$this->Event->read(null, $id);
		// check for if private and user not authorised to edit, go away
		if (!$this->_isSiteAdmin() && !($this->userRole['perm_sync'] && $this->_isRest())) {
			if (($this->Event->data['Event']['org'] != $this->_checkOrg()) || !($this->userRole['perm_modify'])) {
				$this->Session->setFlash(__('You are not authorised to do that. Please considering using the propose attribute feature.'));
				$this->redirect(array('controller' => 'events', 'action' => 'index'));
			}
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			if ($this->_isRest()) {
				$saveEvent = false;
				if ($this->_isRest()) $this->request->data = $this->updateXMLArray($this->request->data, false);
				// Workaround for different structure in XML/array than what CakePHP expects
				$this->Event->cleanupEventArrayFromXML($this->request->data);

				// the event_id field is not set (normal) so make sure no validation errors are thrown
				// LATER do this with	 $this->validator()->remove('event_id');
				unset($this->Event->Attribute->validate['event_id']);
				unset($this->Event->Attribute->validate['value']['unique']); // otherwise gives bugs because event_id is not set
				// http://book.cakephp.org/2.0/en/models/saving-your-data.html
				// Creating or updating is controlled by the models id field.
				// If $Model->id is set, the record with this primary key is updated.
				// Otherwise a new record is created

				// reposition to get the event.id with given uuid
				$existingEvent = $this->Event->findByUuid($this->request->data['Event']['uuid']);
				// If the event exists...
				if (count($existingEvent)) {
					$this->request->data['Event']['id'] = $existingEvent['Event']['id'];
					// Conditions affecting all:
					// user.org == event.org
					// edit timestamp newer than existing event timestamp
					if (isset($this->request->data['Event']['timestamp']) && $this->request->data['Event']['timestamp'] > $existingEvent['Event']['timestamp']) {
						// If the above is true, we have two more options:
						// For users that are of the creating org of the event, always allow the edit
						// For users that are sync users, only allow the edit if the event is locked
						if ($existingEvent['Event']['orgc'] === $this->_checkOrg()
								|| ($this->userRole['perm_sync'] && $existingEvent['Event']['locked'])) {
							// Only allow an edit if this is true!
							$saveEvent = true;
						}
					}
				}
				$fieldList = array(
						'Event' => array('date', 'threat_level_id', 'analysis', 'info', 'published', 'uuid', 'from', 'distribution', 'timestamp'),
						'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'revision', 'distribution', 'timestamp')
				);

				$c = 0;
				if (isset($this->request->data['Attribute'])) {
					foreach ($this->request->data['Attribute'] as $attribute) {
						$existingAttribute = $this->Event->Attribute->findByUuid($attribute['uuid']);
						if (count($existingAttribute)) {
							$this->request->data['Attribute'][$c]['id'] = $existingAttribute['Attribute']['id'];
							// Check if the attribute's timestamp is bigger than the one that already exists.
							// If yes, it means that it's newer, so insert it. If no, it means that it's the same attribute or older - don't insert it, insert the old attribute.
							// Alternatively, we could unset this attribute from the request, but that could lead with issues if we decide that we want to start deleting attributes that don't exist in a pushed event.
							if ($this->request->data['Attribute'][$c]['timestamp'] > $existingAttribute['Attribute']['id']) {

							} else {
								unset($this->request->data['Attribute'][$c]);
								//$this->request->data['Attribute'][$c] = $existingAttribute['Attribute'];
							}
						}
						$c++;
					}
				}
				// this saveAssociated() function will save not only the event, but also the attributes
				// from the attributes attachments are also saved to the disk thanks to the afterSave() fonction of Attribute
				if ($saveEvent) {
					$saveResult = $this->Event->saveAssociated($this->request->data, array('validate' => true, 'fieldList' => $fieldList));
				} else {
					throw new MethodNotAllowedException();
				}
				if ($saveResult) {
					// TODO RESTfull: we now need to compare attributes, to see if we need to do a RESTfull attribute delete
					$message = 'Saved';
					$this->set('event', $this->Event->data);
					//if published -> do the actual publishing
					if ((!empty($this->request->data['Event']['published']) && 1 == $this->request->data['Event']['published'])) {
						// do the necessary actions to publish the event (email, upload,...)
						$this->Event->publish($existingEvent['Event']['id']);
					}

					// REST users want to see the newly created event
					$this->view($this->Event->getId());
					$this->render('view');
					return true;
				} else {
					$message = 'Error';
					$this->set(array('message' => $message,'_serialize' => array('message')));	// $this->Event->validationErrors
					$this->render('edit');
					//throw new MethodNotAllowedException("Validation ERROR: \n".var_export($this->Event->validationErrors, true));
					return false;
				}
			}
			// say what fields are to be updated
			$fieldList = array('date', 'threat_level_id', 'analysis', 'info', 'published', 'distribution', 'timestamp');

			$this->Event->read();
			// always force the org, but do not force it for admins
			if (!$this->_isSiteAdmin()) {
				// set the same org as existed before
				$this->request->data['Event']['org'] = $this->Event->data['Event']['org'];
			}
			// we probably also want to remove the published flag
			$this->request->data['Event']['published'] = 0;
			$date = new DateTime();
			$this->request->data['Event']['timestamp'] = $date->getTimestamp();
			if ($this->Event->save($this->request->data, true, $fieldList)) {
				$this->Session->setFlash(__('The event has been saved'));
				$this->redirect(array('action' => 'view', $id));
			} else {
				$this->Session->setFlash(__('The event could not be saved. Please, try again.'));
			}
		} else {
			if(!$this->userRole['perm_modify']) $this->redirect(array('controller' => 'events', 'action' => 'index', 'admin' => false));
			$this->request->data = $this->Event->read(null, $id);
		}

		// combobox for distribution
		$distributions = array_keys($this->Event->distributionDescriptions);
		$distributions = $this->_arrayToValuesIndexArray($distributions);
		$this->set('distributions', $distributions);

		// tooltip for distribution
		$this->set('distributionDescriptions', $this->Event->distributionDescriptions);
		$this->set('distributionLevels', $this->Event->distributionLevels);

		// combobox for types
		$threat_levels = $this->Event->ThreatLevel->find('all');
		$this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
		$this->set('riskDescriptions', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.form_description'));

		// combobox for analysis
		$analysiss = $this->Event->validate['analysis']['rule'][1];
		$analysiss = $this->_arrayToValuesIndexArray($analysiss);
		$this->set('analysiss',$analysiss);

		// tooltip for analysis
		$this->set('analysisDescriptions', $this->Event->analysisDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
        $this->set('sharingGroups', $this->Event->SharingGroup->find('list'));
        $this->set('servers', $this->Event->Server->find('list'));
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);

		$this->set('event', $this->Event->data);
	}

	/**
	 * delete method
	 *
	 * @param int $id
	 * @return void
	 * @throws MethodNotAllowedException
	 * @throws NotFoundException
	 */

	public function delete($id = null) {
		if (!$this->request->is('post') && !$this->_isRest()) {
			throw new MethodNotAllowedException();
		}

		$this->Event->id = $id;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}

		if ('true' == Configure::read('MISP.sync')) {
			// find the uuid
			$result = $this->Event->findById($id);
			$uuid = $result['Event']['uuid'];
		}
		if (!$this->_isSiteAdmin()) {
			$this->Event->read();
			if (!$this->Event->data['Event']['orgc'] == $this->_checkOrg()) {
				throw new MethodNotAllowedException();
			}
		}
		if ($this->Event->delete()) {

			// delete the event from remote servers
			//if ('true' == Configure::read('MISP.sync')) {	// TODO test..(!$this->_isRest()) &&
			//	$this->__deleteEventFromServers($uuid);
			//}
			$this->Session->setFlash(__('Event deleted'));

			// if coming from index, redirect to referer (to have the filter working)
			// else redirect to index
			if (strpos($this->referer(), '/view') !== FALSE)
				$this->redirect(array('action' => 'index'));
			else
				$this->redirect($this->referer(array('action' => 'index')));
		}
		$this->Session->setFlash(__('Event was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

	/**
	 * Uploads this specific event to all remote servers
	 * TODO move this to a component
	 *
	 * @return bool true if success, false if, partly, failed
	 */
	private function __uploadEventToServers($id, $passAlong = null) {
		// make sure we have all the data of the Event
		$this->Event->id = $id;
		$this->Event->recursive = 1;
		$this->Event->read();
		$this->Event->data['Event']['locked'] = 1;
        //$server_ids = Set::extract('/Server/id', $this->Event->data);

		// get a list of the servers
		$this->loadModel('Server');
		$servers = $this->Server->find('all', array(
				'conditions' => array(
                    'Server.id' => Set::extract('/Server/id', $this->Event->data),
                    'Server.push' => true)
		));
		// iterate over the servers and upload the event
		if(empty($servers))
			return true;

		$uploaded = true;
		$failedServers = array();
		App::uses('HttpSocket', 'Network/Http');
		$HttpSocket = new HttpSocket();
		foreach ($servers as &$server) {
			//Skip servers where the event has come from.
			if (($passAlong != $server)) {
				$thisUploaded = $this->Event->uploadEventToServer($this->Event->data, $server, $HttpSocket);
				if (!$thisUploaded) {
					$uploaded = !$uploaded ? $uploaded : $thisUploaded;
					$failedServers[] = $server['Server']['url'];
				}
			}
		}
		if (!$uploaded) {
			return $failedServers;
		} else {
			return true;
		}
	}

	/**
	 * Delets this specific event to all remote servers
	 * TODO move this to a component(?)
	 */
	private function __deleteEventFromServers($uuid) {
		// get a list of the servers
		$this->loadModel('Server');
		$servers = $this->Server->find('all', array(
				'conditions' => array('Server.push' => true)
		));

		// iterate over the servers and upload the event
		if(empty($servers))
			return;

		App::uses('SyncTool', 'Tools');
		foreach ($servers as &$server) {
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
			$this->Event->deleteEventFromServer($uuid, $server, $HttpSocket);
		}
	}

	/**
	 * Publishes the event without sending an alert email
	 *
	 * @throws NotFoundException
	 */
	public function publish($id = null) {
		$this->Event->id = $id;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}
		// update the event and set the from field to the current instance's organisation from the bootstrap. We also need to save id and info for the logs.
		$this->Event->recursive = -1;
		$event = $this->Event->read(null, $id);
		if (!$this->_isSiteAdmin()) {
			if (!$this->userRole['perm_publish'] && !$this->Auth->user('org') === $this->Event->data['Event']['orgc']) {
				throw new MethodNotAllowedException('You don\'t have the permission to do that.');
			}
		}
		// only allow form submit CSRF protection.
		if ($this->request->is('post') || $this->request->is('put')) {
			// Performs all the actions required to publish an event
			$result = $this->Event->publishRouter($id, null, $this->Auth->user('org'), $this->Auth->user('email'));
			if (!Configure::read('MISP.background_jobs')) {
				if (!is_array($result)) {
					// redirect to the view event page
					$this->Session->setFlash(__('Event published, but NO mail sent to any participants.', true));
				} else {
					$lastResult = array_pop($result);
					$resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
					$this->Session->setFlash(__(sprintf('Event not published to %s, re-try later. If the issue persists, make sure that the correct sync user credentials are used for the server link and that the sync user on the remote server has authentication privileges.', $resultString), true));
				}
			} else {
				$this->Session->setFlash(__('Job queued.'));
			}
			$this->redirect(array('action' => 'view', $id));
		}
	}

	/**
	 * Send out an alert email to all the users that wanted to be notified.
	 * Users with a GPG key will get the mail encrypted, other users will get the mail unencrypted
	 *
	 * @throws NotFoundException
	 */
	public function alert($id = null) {
		$this->Event->id = $id;
		$this->Event->recursive = 0;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}
		$this->Event->recursive = -1;
		$this->Event->read(null, $id);
		if (!$this->_isSiteAdmin()) {
			if (!$this->userRole['perm_publish'] && !$this->Auth->user('org') === $this->Event->data['Event']['orgc']) {
				throw new MethodNotAllowedException('You don\'t have the permission to do that.');
			}
		}
		// only allow form submit CSRF protection.
		if ($this->request->is('post') || $this->request->is('put')) {
			// send out the email
			$emailResult = $this->Event->sendAlertEmailRouter($id, $this->Auth->user(), $this->_isSiteAdmin());
			if (is_bool($emailResult) && $emailResult = true) {
				// Performs all the actions required to publish an event
				$result = $this->Event->publishRouter($id, null, $this->Auth->user('org'), $this->Auth->user('email'));
				if (!is_array($result)) {

					// redirect to the view event page
					$this->Session->setFlash(__('Email sent to all participants.', true));
				} else {
					$lastResult = array_pop($result);
					$resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
					$this->Session->setFlash(__(sprintf('Not published given no connection to %s but email sent to all participants.', $resultString), true));
				}
			} elseif (!is_bool($emailResult)) {
				// Performs all the actions required to publish an event
				$result = $this->Event->publish($id);
				if (!is_array($result)) {

					// redirect to the view event page
					$this->Session->setFlash(__('Published but no email sent given GnuPG is not configured.', true));
				} else {
					$lastResult = array_pop($result);
					$resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
					$this->Session->setFlash(__(sprintf('Not published given no connection to %s but no email sent given GnuPG is not configured.', $resultString), true));
				}
			} else {
				$this->Session->setFlash(__('Sending of email failed', true), 'default', array(), 'error');
			}
			$this->redirect(array('action' => 'view', $id));
		}
	}

	private function __sendAlertEmail($id) {
		$this->Event->recursive = 1;
		$event = $this->Event->read(null, $id);

		// The mail body, h() is NOT needed as we are sending plain-text mails.
		$body = "";
		$body .= '----------------------------------------------' . "\n";
		$appendlen = 20;
		$body .= 'URL         : ' . Configure::read('CyDefSIG.baseurl') . '/events/view/' . $event['Event']['id'] . "\n";
		$body .= 'Event       : ' . $event['Event']['id'] . "\n";
		$body .= 'Date        : ' . $event['Event']['date'] . "\n";
		if ('true' == Configure::read('CyDefSIG.showorg')) {
			$body .= 'Reported by : ' . $event['Event']['org'] . "\n";
		}
		$body .= 'Risk        : ' . $event['ThreatLevel']['name'] . "\n";
		$body .= 'Analysis    : ' . $this->Event->analysisLevels[$event['Event']['analysis']] . "\n";
		$body .= 'Info  : ' . "\n";
		$body .= $event['Event']['info'] . "\n";
		$relatedEvents = $this->Event->getRelatedEvents($this->Auth->user(), $this->_isSiteAdmin());
		if (!empty($relatedEvents)) {
			$body .= '----------------------------------------------' . "\n";
			$body .= 'Related to : '. "\n";
			foreach ($relatedEvents as &$relatedEvent) {
				$body .= Configure::read('CyDefSIG.baseurl') . '/events/view/' . $relatedEvent['Event']['id'] . ' (' . $relatedEvent['Event']['date'] . ') ' ."\n";

			}
			$body .= '----------------------------------------------' . "\n";
		}
		$body .= 'Attributes  :' . "\n";
		$bodyTempOther = "";

		if (isset($event['Attribute'])) {
			foreach ($event['Attribute'] as &$attribute) {
				$line = '- ' . $attribute['type'] . str_repeat(' ', $appendlen - 2 - strlen($attribute['type'])) . ': ' . $attribute['value'] . "\n";
				if ('other' == $attribute['type']) // append the 'other' attribute types to the bottom.
					$bodyTempOther .= $line;
				else $body .= $line;
			}
		}
		if (!empty($bodyTempOther)) {
			$body .= "\n";
		}
		$body .= $bodyTempOther;	// append the 'other' attribute types to the bottom.
		$body .= '----------------------------------------------' . "\n";
		// find out whether the event is private, to limit the alerted user's list to the org only
		if ($event['Event']['distribution'] == 0) {
			$eventIsPrivate = true;
		} else {
			$eventIsPrivate = false;
		}
		// sign the body
		require_once 'Crypt/GPG.php';
		try {
			$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));	// , 'debug' => true
			$gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
			$bodySigned = $gpg->sign($body, Crypt_GPG::SIGN_MODE_CLEAR);
			//$this->loadModel('User');

			//
			// Build a list of the recipients that get a non-encrypted mail
			// But only do this if it is allowed in the bootstrap.php file.
			//
			if ($eventIsPrivate) {
				$conditions = array('User.autoalert' => 1, 'User.gpgkey =' => "", 'User.org =' => $event['Event']['org']);
			} else {
				$conditions = array('User.autoalert' => 1, 'User.gpgkey =' => "");
			}
			if ('false' == Configure::read('GnuPG.onlyencrypted')) {
                $groups = Set::extract('/SharingGroup/id', $event);
                if(!empty($groups)){
                    $users = $this->Event->SharingGroup->find('all', array(
                        'conditions' => array('SharingGroup.id' => $groups),
                        'contain' => array('Organisation' => array('User')),
                        'recursive' => -1,
                    ));

                    $alertUsers = Set::extract('/Organisation/User', $users);
                }else{
                    $alertUsers = $this->User->find('all', array(
                        'conditions' => $conditions,
                        'recursive' => 0,
                    ));
                }

				foreach ($alertUsers as &$user) {
					// prepare the the unencrypted email
					$this->Email->from = Configure::read('CyDefSIG.email');
					$this->Email->to = $user['User']['email'];
					$this->Email->subject = "[" . Configure::read('CyDefSIG.org') . " " . Configure::read('CyDefSIG.name') . "] Event " . $id . " - " . $event['ThreatLevel']['name'] . " - TLP Amber";
					$this->Email->template = 'body';
					$this->Email->sendAs = 'text';	// both text or html
					$this->set('body', $bodySigned);
					// send it
					$this->Email->send();
					// If you wish to send multiple emails using a loop, you'll need
					// to reset the email fields using the reset method of the Email component.
					$this->Email->reset();
				}
			}
			//
			// Build a list of the recipients that wish to receive encrypted mails.
			//
			if ($eventIsPrivate) {
				$conditions = array('User.autoalert' => 1, 'User.gpgkey !=' => "", 'User.org =' => $event['Event']['org']);
			} else {
				$conditions = array('User.autoalert' => 1, 'User.gpgkey !=' => "");
			}

            $groups = Set::extract('/SharingGroup/id', $event);
            if(!empty($groups)){
                $users = $this->Event->SharingGroup->find('all', array(
                    'conditions' => array('SharingGroup.id' => $groups),
                    'contain' => array('Organisation' => array('User')),
                    'recursive' => -1,
                ));

                $alertUsers = Set::extract('/Organisation/User', $users);
            }else{
                $alertUsers = $this->User->find('all', array(
                    'conditions' => $conditions,
                    'recursive' => 0
                ));
            }

			// encrypt the mail for each user and send it separately
			foreach ($alertUsers as &$user) {
				// send the email
				$this->Email->from = Configure::read('CyDefSIG.email');
				$this->Email->to = $user['User']['email'];
				$this->Email->subject = "[" . Configure::read('CyDefSIG.org') . " " . Configure::read('CyDefSIG.name') . "] Event " . $id . " - " . $event['ThreatLevel']['name'] . " - TLP Amber";
				$this->Email->template = 'body';
				$this->Email->sendAs = 'text';		// both text or html

				// import the key of the user into the keyring
				// this is not really necessary, but it enables us to find
				// the correct key-id even if it is not the same as the emailaddress
				$keyImportOutput = $gpg->importKey($user['User']['gpgkey']);
				// say what key should be used to encrypt
				try {
					$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));
					$gpg->addEncryptKey($keyImportOutput['fingerprint']); // use the key that was given in the import

					$bodyEncSig = $gpg->encrypt($bodySigned, true);

					$this->set('body', $bodyEncSig);
					$this->Email->send();
				} catch (Exception $e){
					// catch errors like expired PGP keys
					$this->log($e->getMessage());
					// no need to return here, as we want to send out mails to the other users if GPG encryption fails for a single user
				}
				// If you wish to send multiple emails using a loop, you'll need
				// to reset the email fields using the reset method of the Email component.
				$this->Email->reset();
			}
		} catch (Exception $e){
			// catch errors like expired PGP keys
			$this->log($e->getMessage());
			return $e->getMessage();
		}

		// LATER check if sending email succeeded and return appropriate result
		return true;
	}

	/**
	 * Send out an contact email to the person who posted the event.
	 * Users with a GPG key will get the mail encrypted, other users will get the mail unencrypted
	 *
	 * @throws NotFoundException
	 */
	public function contact($id = null) {
		$this->Event->id = $id;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}

		// User has filled in his contact form, send out the email.
		if ($this->request->is('post') || $this->request->is('put')) {
			$message = $this->request->data['Event']['message'];
			$all = $this->request->data['Event']['person'];
			if ($this->Event->sendContactEmailRouter($id, $message, $all, $this->Auth->user(), $this->_isSiteAdmin())) {
				// redirect to the view event page
				$this->Session->setFlash(__('Email sent to the reporter.', true));
			} else {
				$this->Session->setFlash(__('Sending of email failed', true), 'default', array(), 'error');
			}
			$this->redirect(array('action' => 'view', $id));
		}
		// User didn't see the contact form yet. Present it to him.
		if (empty($this->data)) {
			$this->data = $this->Event->read(null, $id);
		}
	}

	public function automation() {
		// Simply display a static view
		if (!$this->userRole['perm_auth']) {
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		}
		// generate the list of Attribute types
		$this->loadModel('Attribute');
		$this->set('sigTypes', array_keys($this->Attribute->typeDefinitions));
	}

	public function export() {
		// Check if the background jobs are enabled - if not, fall back to old export page.
		if (Configure::read('MISP.background_jobs')) {
			$now = time();

			// as a site admin we'll use the ADMIN identifier, not to overwrite the cached files of our own org with a file that includes too much data.
			if ($this->_isSiteAdmin()) {
				$useOrg = 'ADMIN';
				$conditions = null;
			} else {
				$useOrg = $this->Auth->User('org');
				$conditions['OR'][] = array('orgc' => $this->Auth->user('org'));
				$conditions['OR'][] = array('distribution >' => 0);
			}
			$this->Event->recursive = -1;
			$newestEvent = $this->Event->find('first', array(
				'conditions' => $conditions,
				'fields' => 'timestamp',
				'order' => 'Event.timestamp DESC',
			));
			$this->loadModel('Job');
			foreach ($this->Event->export_types as $k => $type) {
				$job = $this->Job->find('first', array(
						'fields' => array('id', 'progress'),
						'conditions' => array(
								'job_type' => 'cache_' . $k,
								'org' => $useOrg
							),
						'order' => array('Job.id' => 'desc')
				));
				$dir = new Folder(APP . 'tmp/cached_exports/' . $k);
				if ($k === 'text') {
					// Since all of the text export files are generated together, we might as well just check for a single one md5.
					$file = new File($dir->pwd() . DS . 'misp.text_md5.' . $useOrg . $type['extension']);
				} else {
					$file = new File($dir->pwd() . DS . 'misp.' . $k . '.' . $useOrg . $type['extension']);
				}
				if (!$file->exists()) {
					$lastModified = 'N/A';
					$this->Event->export_types[$k]['recommendation'] = 1;
				} else {
					$fileChange = $file->lastChange();
					$lastModified = $this->__timeDifference($now, $fileChange);
					if ($fileChange > $newestEvent['Event']['timestamp']) {
						$this->Event->export_types[$k]['recommendation'] = 0;
					} else {
						$this->Event->export_types[$k]['recommendation'] = 1;
					}
				}

				$this->Event->export_types[$k]['lastModified'] = $lastModified;
				if (!empty($job)) {
					$this->Event->export_types[$k]['job_id'] = $job['Job']['id'];
					$this->Event->export_types[$k]['progress'] = $job['Job']['progress'];
				} else {
					$this->Event->export_types[$k]['job_id'] = -1;
					$this->Event->export_types[$k]['progress'] = 0;
				}
				//$this->Event->export_types[$k]['recommendation']
			}
			$this->set('useOrg', $useOrg);
			$this->set('export_types', $this->Event->export_types);
			// generate the list of Attribute types
			$this->loadModel('Attribute');
			//$lastModified = strftime("%d, %m, %Y, %T", $lastModified);
			$this->set('sigTypes', array_keys($this->Attribute->typeDefinitions));
		} else {
			// generate the list of Attribute types
			$this->loadModel('Attribute');
			//$lastModified = strftime("%d, %m, %Y, %T", $lastModified);
			$this->set('sigTypes', array_keys($this->Attribute->typeDefinitions));
			$this->render('/Events/export_alternate');
		}
	}


	public function downloadExport($type, $extra = null) {
		if ($this->_isSiteAdmin()) $org = 'ADMIN';
		else $org = $this->Auth->user('org');
		$this->autoRender = false;
		if ($extra != null) $extra = '_' . $extra;
		$this->response->type($this->Event->export_types[$type]['extension']);
		$path = 'tmp/cached_exports/' . $type . DS . 'misp.' . strtolower($this->Event->export_types[$type]['type']) . $extra . '.' . $org . $this->Event->export_types[$type]['extension'];
		$newFileName = 'misp.' . $this->Event->export_types[$type]['type'] . '.' . $org . $this->Event->export_types[$type]['extension'];
		$this->response->file($path, array('download' => true));
	}

	private function __timeDifference($now, $then) {
		$periods = array("second", "minute", "hour", "day", "week", "month", "year");
		$lengths = array("60","60","24","7","4.35","12");
		$difference = $now - $then;
		for($j = 0; $difference >= $lengths[$j] && $j < count($lengths)-1; $j++) {
			$difference /= $lengths[$j];
		}
		$difference = round($difference);
		if($difference != 1) {
			$periods[$j].= "s";
		}
		return $difference . " " . $periods[$j] . " ago";
	}

	public function xml($key, $eventid=null, $withAttachment = false, $tags = '') {
		if ($eventid === 'null' || $eventid ==='false') $eventid=null;
		if ($withAttachment === 'null' || $withAttachment ==='false') $withAttachment = false;
		if ($key != 'download') {
			// check if the key is valid -> search for users based on key
			$user = $this->checkAuthUser($key);
			if (!$user) {
				throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
			}
			// display the full xml
			$this->response->type('xml');	// set the content type
			$this->layout = 'xml/default';
			$this->header('Content-Disposition: download; filename="misp.xml"');
		} else {
			if (!$this->Auth->user('id')) {
				throw new UnauthorizedException('You have to be logged in to do that.');
			}
			// display the full xml
			$this->response->type('xml');	// set the content type
			$this->layout = 'xml/default';
			if ($eventid == null) {
				$this->header('Content-Disposition: download; filename="misp.export.all.xml"');
			} else {
				$this->header('Content-Disposition: download; filename="misp.export.event' . $eventid . '.xml"');
			}
		}
		$results = $this->__fetchEvent($eventid, null, null, false, $tags);
		if ($withAttachment) {
			$this->loadModel('Attribute');
			foreach ($results[0]['Attribute'] as &$attribute) {
				if ($this->Attribute->typeIsAttachment($attribute['type'])) {
					$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
					$attribute['data'] = $encodedFile;
				}
			}
		}
		// Whitelist check
		$this->loadModel('Whitelist');
		$results = $this->Whitelist->removeWhitelistedFromArray($results, false);
		if ($eventid) {
			$this->header('Content-Disposition: download; filename="misp.event' . $eventid . '.export.xml"');
		} else {
			$this->header('Content-Disposition: download; filename="misp.export.xml"');
		}
		$this->response->type('xml');
		$this->set('results', $results);
	}

	// Grab an event or a list of events for the event view or any of the XML exports. The returned object includes an array of events (or an array that only includes a single event if an ID was given)
	// Included with the event are the attached attributes, shadow attributes, related events, related attribute information for the event view and the creating user's email address where appropriate
	private function __fetchEvent($eventid = null, $idList = null, $orgFromFetch = null, $isSiteAdmin = false, $tags = '') {
		// if we come from automation, we may not be logged in - instead we used an auth key in the URL.
		if (!empty($orgFromFetch)) {
			$org = $orgFromFetch;
		} else {
			$org = $this->_checkOrg();
			$isSiteAdmin = $this->_isSiteAdmin();
		}

		$conditionsAttributes = array();
		$conditionsShadowAttributes = array();
		//restricting to non-private or same org if the user is not a site-admin.
		if (!$isSiteAdmin) {
			if (!empty($orgFromFetch)) $org = $orgFromFetch;
			else $org = $this->_checkOrg();
			$conditions['AND']['OR'] = array(
						'Event.distribution >' => 0,
						'Event.org LIKE' => $org
					);
			$conditionsAttributes['OR'] = array(
						'Attribute.distribution >' => 0,
						'(SELECT events.org FROM events WHERE events.id = Attribute.event_id) LIKE' => $org
					);
			$conditionsShadowAttributes['OR'] = array(
					// We are currently looking at events.org matching the user's org, but later on, once we start syncing shadow attributes, we may want to change this to orgc
					// Right now the org that currently owns the event on an instance can see, accept and decline these requests, but in the long run once we can distribute
					// the requests back to the creator, we may want to leave these decisions up to them.
					array('(SELECT events.org FROM events WHERE events.id = ShadowAttribute.event_id) LIKE' => $org),
					array('ShadowAttribute.org LIKE' => $org),
				);
		}

		if ($idList) {
			$conditions['AND'][] = array('Event.id' => $idList);
		}
		// removing this for now, we export the to_ids == 0 attributes too, since there is a to_ids field indicating it in the .xml
		// $conditionsAttributes['AND'] = array('Attribute.to_ids =' => 1);
		// Same idea for the published. Just adjust the tools to check for this
		// TODO: It is important to make sure that this is documented
		// $conditions['AND'][] = array('Event.published =' => 1);

		// do not expose all the data ...
		$fields = array('Event.id', 'Event.org', 'Event.date','Event.info', 'Event.published', 'Event.uuid', 'Event.attribute_count', 'Event.analysis', 'Event.timestamp', 'Event.distribution', 'Event.proposal_email_lock', 'Event.orgc', 'Event.user_id', 'Event.locked');
		$fieldsAtt = array('Attribute.id', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids', 'Attribute.uuid', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.timestamp', 'Attribute.comment');
		$fieldsShadowAtt = array('ShadowAttribute.id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.value', 'ShadowAttribute.to_ids', 'ShadowAttribute.uuid', 'ShadowAttribute.event_id', 'ShadowAttribute.old_id');

		$params = array('conditions' => $conditions,
				'recursive' => 0,
				'fields' => $fields,
				'contain' => array(
                        'SharingGroup',
						'ThreatLevel' => array(
							'fields' => array('ThreatLevel.name')
						),
						'Attribute' => array(
								'fields' => $fieldsAtt,
								'conditions' => $conditionsAttributes,
						),
						'ShadowAttribute' => array(
								'fields' => $fieldsShadowAtt,
								'conditions' => $conditionsShadowAttributes,
						),
				)
		);

		if(!$isSiteAdmin){
            $org_sharing = $this->Event->User->Organisation->read(null, $this->Auth->user('organisation_id'));
            $params['contain']['User'] = array('fields' => 'email');
            if(!empty($org_sharing)){
                $params['joins'] = array(
                        array(
                            'table' => 'events_sharing_groups',
                            'alias' => 'EventsSharingGroup',
                            'type' => 'inner',
                            'conditions'=> array('EventsSharingGroup.event_id = Event.id')
                        ),
                        array(
                            'table' => 'sharing_groups',
                            'alias' => 'SharingGroup',
                            'type' => 'inner',
                            'conditions'=> array(
                                'SharingGroup.id = EventsSharingGroup.sharing_group_id',
                                'SharingGroup.id' => Set::extract('/SharingGroup/id', $org_sharing)
                                )
                        )
                    );
            }
        }
		$results = $this->Event->find('all', $params);
		// Do some refactoring with the event
		foreach ($results as $eventKey => &$event) {
			// Let's find all the related events and attach it to the event itself
			$results[$eventKey]['RelatedEvent'] = $this->Event->getRelatedEvents($this->Auth->user(), $this->_isSiteAdmin(), $event['Event']['id']);
			// Let's also find all the relations for the attributes - this won't be in the xml export though
			$results[$eventKey]['RelatedAttribute'] = $this->Event->getRelatedAttributes($this->Auth->user(), $this->_isSiteAdmin(), $event['Event']['id']);
			foreach ($event['Attribute'] as $key => &$attribute) {
				$attribute['ShadowAttribute'] = array();
				// If a shadowattribute can be linked to an attribute, link it to it then remove it from the event
				// This is to differentiate between proposals that were made to an attribute for modification and between proposals for new attributes
				foreach ($event['ShadowAttribute'] as $k => &$sa) {
					if(!empty($sa['old_id'])) {
						if ($sa['old_id'] == $attribute['id']) {
							$results[$eventKey]['Attribute'][$key]['ShadowAttribute'][] = $sa;
							unset($results[$eventKey]['ShadowAttribute'][$k]);
						}
					}
				}
			}
		}
		return $results;
	}

	public function nids($format = 'suricata', $key = '', $id = null, $continue = false, $tags = '') {
		if ($id === 'null') $id = null;
		if ($continue === 'false') $continue = false;
		if ($continue === 'true') $continue = true;
		// backwards compatibility, swap key and format
		if ($format != 'snort' && $format != 'suricata') {
			$key = $format;
			$format = 'suricata'; // default format
		}
		$this->response->type('txt');	// set the content type
		$this->header('Content-Disposition: download; filename="misp.rules"');
		$this->layout = 'text/default';
		if ($key != 'download') {
			// check if the key is valid -> search for users based on key
			$user = $this->checkAuthUser($key);
			if (!$user) {
				throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
			}
		} else {
			// check if there's a user logged in or not
			if (!$this->Auth->user('id')) {
				throw new UnauthorizedException('You have to be logged in to do that.');
			}
			$user = $this->checkAuthUser($this->Auth->user('authkey'));
		}

		// display the full snort rulebase
		$this->loadModel('Attribute');
		$rules = $this->Attribute->nids($user['User']['siteAdmin'], $user['User']['org'], $format, $user['User']['nids_sid'], $id, $continue, $tags);
		$this->set('rules', $rules);
	}

	public function hids($type, $key, $tags = '') {
		$this->response->type('txt');	// set the content type
		$this->header('Content-Disposition: download; filename="misp.' . $type . '.rules"');
		$this->layout = 'text/default';
		if ($key != 'download') {
			// check if the key is valid -> search for users based on key
			$user = $this->checkAuthUser($key);
			if (!$user) {
				throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
			}
		} else {
			// check if there's a user logged in or not
			if (!$this->Auth->user('id')) {
				throw new UnauthorizedException('You have to be logged in to do that.');
			}
			$user = $this->checkAuthUser($this->Auth->user('authkey'));
		}
		$this->loadModel('Attribute');

		$rules = $this->Attribute->hids($user['User']['siteAdmin'], $user['User']['org'], $type, $tags);
		$this->set('rules', $rules);
	}

	// csv function
	// Usage: csv($key, $eventid)   - key can be a valid auth key or the string 'download'. Download requires the user to be logged in interactively and will generate a .csv file
	// $eventid can be one of 3 options: left empty it will get all the visible to_ids attributes,
	public function csv($key, $eventid=0, $ignore=0, $tags = '') {
		$list = array();

		if ($key != 'download') {
			// check if the key is valid -> search for users based on key
			$user = $this->checkAuthUser($key);
			if (!$user) {
				throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
			}
			$isSiteAdmin = $user['User']['siteAdmin'];
			$org = $user['User']['org'];
		} else {
			if (!$this->Auth->user('id')) {
				throw new UnauthorizedException('You have to be logged in to do that.');
			}
			$isSiteAdmin = $this->_isSiteAdmin();
			$org = $this->Auth->user('org');
		}

		// if it's a search, grab the attributeIDList from the session and get the IDs from it. Use those as the condition
		// We don't need to look out for permissions since that's filtered by the search itself
		// We just want all the attributes found by the search
		if ($eventid === 'search') {
			$list = $this->Session->read('search_find_attributeidlist');
		}
		$attributes = $this->Event->csv($org, $isSiteAdmin, $eventid, $ignore, $list, $tags);
		$this->loadModel('Whitelist');
		$final = array();
		$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
		foreach ($attributes as $attribute) {
			$final[] = $attribute['Attribute']['uuid'] . ',' . $attribute['Attribute']['event_id'] . ',' . $attribute['Attribute']['category'] . ',' . $attribute['Attribute']['type'] . ',' . $attribute['Attribute']['value'];
		}

		$this->response->type('csv');	// set the content type
		if ($eventid == 0) {
			$this->header('Content-Disposition: download; filename="misp.all_attributes.csv"');
		} else if ($eventid === 'search') {
			$this->header('Content-Disposition: download; filename="misp.search_result.csv"');
		} else {
			$this->header('Content-Disposition: download; filename="misp.event_' . $eventid . '.csv"');
		}
		$this->layout = 'text/default';
		$this->set('headers', array('uuid', 'event_id', 'category', 'type', 'value'));
		$this->set('final', $final);
	}

	//public function dot($key) {
	//	// check if the key is valid -> search for users based on key
	//	$this->loadModel('User');
	//	// no input sanitization necessary, it's done by model
	//	$this->User->recursive=0;
	//	$user = $this->User->findByAuthkey($key);
	//	if (empty($user)) {
	//		throw new UnauthorizedException('Incorrect authentication key');
	//	}
	//	// display the full snort rulebase
	//	$this->response->type('txt');	// set the content type
	//	$this->header('Content-Disposition: inline; filename="MISP.rules"');
	//	$this->layout = 'text/default';

	//	$rules= array();
	//	$this->loadModel('Attribute');

	//	$params = array(
	//			'recursive' => 0,
	//			'fields' => array('Attribute.*')
	//	);
	//	$items = $this->Attribute->find('all', $params);

	//	$composite_types = $this->Attribute->getCompositeTypes();
	//	// rebuild the array with the correct data
	//	foreach ($items as &$item) {
	//		if (in_array($item['Attribute']['type'], $composite_types)) {
	//			// create a new item that will contain value2
	//			$new_item = $item;
	//			// set the correct type for the first item
	//			$pieces = explode('|', $item['Attribute']['type']);
	//			$item['Attribute']['type'] = $pieces[0];
	//			// set the correct data for the new item
	//			$new_item['Attribute']['type'] = (isset($pieces[1]))? $pieces[1] : 'md5';
	//			$new_item['Attribute']['value'] = $item['Attribute']['value2'];
	//			unset($new_item['Attribute']['value1']);
	//			unset($new_item['Attribute']['value2']);
	//			// store the new item
	//			$items[] = $new_item;
	//		}
	//		// set the correct fields for the attribute
	//		if (isset($item['Attribute']['value1'])) {
	//			$item['Attribute']['value'] = $item['Attribute']['value1'];
	//		}
	//		unset($item['Attribute']['value1']);
	//		unset($item['Attribute']['value2']);
	//	}
	//	debug($items);

	//	// iterate over the array to build the GV links
	//	require_once 'Image/GraphViz.php';
	//	$gv = new Image_GraphViz();
	//	$gv->addEdge(array('wake up'		=> 'visit bathroom'));
	//	$gv->addEdge(array('visit bathroom' => 'make coffee'));
	//	foreach ($items as &$item) {
	//		$gv->addNode('Node 1',
	//				array(''));
	//	}
	//	debug($gv);
	//	$gv->image();
	//}

	public function _addGfiZip($id) {
		if (!empty($this->data) && $this->data['Event']['submittedgfi']['size'] > 0 &&
				is_uploaded_file($this->data['Event']['submittedgfi']['tmp_name'])) {
			$zipData = fread(fopen($this->data['Event']['submittedgfi']['tmp_name'], "r"),
					$this->data['Event']['submittedgfi']['size']);

			// write
			$rootDir = APP . "files" . DS . $id . DS;
			App::uses('Folder', 'Utility');
			$dir = new Folder($rootDir, true);
			$destpath = $rootDir;
			$file = new File ($destpath);
			if (!preg_match('@^[\w-,\s,\.]+\.[A-Za-z0-9_]{2,4}$@', $this->data['Event']['submittedgfi']['name'])) throw new Exception ('Filename not allowed');
			if (PHP_OS == 'WINNT') {
				$zipfile = new File ($destpath . DS . $this->data['Event']['submittedgfi']['name']);
			} else {
				$zipfile = new File ($destpath . $this->data['Event']['submittedgfi']['name']);
			}

			$result = $zipfile->write($zipData);
			if (!$result) $this->Session->setFlash(__('Problem with writing the zip file. Please report to administrator.'));
			// extract zip..
			$execRetval = '';
			$execOutput = array();
			exec("unzip " . $zipfile->path . ' -d ' . $rootDir, $execOutput, $execRetval);
			if ($execRetval != 0) {	// not EXIT_SUCCESS
				// do some?
				throw new Exception('An error has occured while attempting to unzip the GFI sandbox .zip file. We apologise for the inconvenience.');
			}

			// now open the xml..
			if (PHP_OS == 'WINNT') {
				$xml = $rootDir . 'Analysis' . DS . 'analysis.xml';
			} else {
				$xml = $rootDir . DS . 'Analysis' . DS . 'analysis.xml';
			}
			$fileData = fread(fopen($xml, "r"), $this->data['Event']['submittedgfi']['size']);

			// read XML
			$this->_readGfiXML($fileData, $id);
		}
	}

	public function _addIOCFile($id) {
		if (!empty($this->data) && $this->data['Event']['submittedioc']['size'] > 0 &&
				is_uploaded_file($this->data['Event']['submittedioc']['tmp_name'])) {
			$iocData = fread(fopen($this->data['Event']['submittedioc']['tmp_name'], "r"),
					$this->data['Event']['submittedioc']['size']);
			// write
			$rootDir = APP . "files" . DS . $id . DS;
			App::uses('Folder', 'Utility');
			$dir = new Folder($rootDir . 'ioc', true);
			$destpath = $rootDir . 'ioc';
			$file = new File ($destpath);
			if (!preg_match('@^[\w-,\s,\.]+\.[A-Za-z0-9_]{2,4}$@', $this->data['Event']['submittedioc']['name'])) throw new Exception ('Filename not allowed');
			$iocfile = new File ($destpath . DS . $this->data['Event']['submittedioc']['name']);
			$result = $iocfile->write($iocData);
			if (!$result) $this->Session->setFlash(__('Problem with writing the ioc file. Please report to administrator.'));

			// now open the xml..
			$xml = $rootDir . DS . 'Analysis' . DS . 'analysis.xml';
			$fileData = fread(fopen($destpath . DS . $this->data['Event']['submittedioc']['name'], "r"), $this->data['Event']['submittedioc']['size']);
			// Load event and populate the event data
			$this->Event->id = $id;
			$this->Event->recursive = -1;
			if (!$this->Event->exists()) {
				throw new NotFoundException(__('Invalid event'));
			}
			$this->Event->read(null, $id);
			$saveEvent['Event'] = $this->Event->data['Event'];
			$saveEvent['Event']['published'] = false;
			$dist = '3';
			if (Configure::read('MISP.default_attribute_distribution') != null) {
				if (Configure::read('MISP.default_attribute_distribution') === 'event') {
					$dist = $this->Event->data['Event']['distribution'];
				} else {
					$dist = '';
					$dist .= Configure::read('MISP.default_attribute_distribution');
				}
			}
			// read XML
			$event = $this->IOCImport->readXML($fileData, $id, $dist);

			// make some changes to have $saveEvent in the format that is needed to save the event together with its attributes
			$fails = $event['Fails'];
			$saveEvent['Attribute'] = $event['Attribute'];
			// we've already stored these elsewhere, unset them so we can extract the event related data
			unset($event['Attribute']);
			unset($event['Fails']);

			// Keep this for later if we want to let an ioc create the event data automatically in a later version
			// save the event related data into $saveEvent['Event']
			//$saveEvent['Event'] = $event;
			//$saveEvent['Event']['id'] = $id;

			$fieldList = array(
					'Event' => array('published', 'timestamp'),
					'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'distribution', 'timestamp', 'comment')
			);
			// Save it all
			$saveResult = $this->Event->saveAssociated($saveEvent, array('validate' => true, 'fieldList' => $fieldList));

			// set stuff for the view and render the showIOCResults view.
			$this->set('attributes', $saveEvent['Attribute']);
			if (isset($fails)) {
				$this->set('fails', $fails);
			}
			$this->set('eventId', $id);
			$this->set('graph', $event['Graph']);
			$this->set('saveEvent', $saveEvent);
			$this->render('showIOCResults');
		}
	}

	public function _addXMLFile() {
		if (!empty($this->data) && $this->data['Event']['submittedxml']['size'] > 0 &&
		is_uploaded_file($this->data['Event']['submittedxml']['tmp_name'])) {
			$xmlData = fread(fopen($this->data['Event']['submittedxml']['tmp_name'], "r"),
					$this->data['Event']['submittedxml']['size']);
			App::uses('Xml', 'Utility');
			$xmlArray = Xml::toArray(Xml::build($xmlData));

			// In case we receive an event that is not encapsulated in a response. This should never happen (unless it's a copy+paste fail),
			// but just in case, let's clean it up anyway.
			if (isset($xmlArray['Event'])) {
				$xmlArray['response']['Event'] = $xmlArray['Event'];
				unset($xmlArray['Event']);
			}

			if (!isset($xmlArray['response']) || !isset($xmlArray['response']['Event'])) {
				throw new Exception('This is not a valid MISP XML file.');
			}

			$xmlArray = $this->Event->updateXMLArray($xmlArray);

			if (isset($xmlArray['response']['Event'][0])) {
				foreach ($xmlArray['response']['Event'] as $event) {
					$temp['Event'] = $event;
					$this->Event->_add($temp, true, $this->Auth->user());
				}
			} else {
				$temp['Event'] = $xmlArray['response']['Event'];
				$this->Event->_add($temp, true, $this->Auth->user());
			}
		}
	}

	public function _readGfiXML($data, $id) {
		$this->loadModel('Attribute');
		$this->Event->recursive = -1;
		$this->Event->read(array('id', 'uuid', 'distribution'), $id);

		// import XML class
		App::uses('Xml', 'Utility');
		// now parse it
		$parsedXml = Xml::build($data, array('return' => 'simplexml'));

		// xpath..

		if (Configure::read('MISP.default_attribute_distribution') != null) {
			if (Configure::read('MISP.default_attribute_distribution') === 'event') {
				$dist = $this->Event->data['Event']['distribution'];
			} else {
				$dist = '';
				$dist .= Configure::read('MISP.default_attribute_distribution');
			}
		}

		//Payload delivery -- malware-sample
		$results = $parsedXml->xpath('/analysis');
		foreach ($results as $result) {
			foreach ($result[0]->attributes() as $key => $val) {
				if ((string)$key == 'filename') $realFileName = (string)$val;
			}
		}
		$realMalware = $realFileName;
		$rootDir = APP . "files" . DS . $id . DS;
		$malware = $rootDir . DS . 'sample';
		$this->Event->Attribute->uploadAttachment($malware,	$realFileName,	true, $id, null, '', $this->Event->data['Event']['uuid'] . '-sample', $dist, true);

		//Network activity -- .pcap
		$realFileName = 'analysis.pcap';
		$rootDir = APP . "files" . DS . $id . DS;
		$malware = $rootDir . DS . 'Analysis' . DS . 'analysis.pcap';
		$this->Event->Attribute->uploadAttachment($malware,	$realFileName,	false, $id, 'Network activity', '', $this->Event->data['Event']['uuid'] . '-analysis.pcap', $dist, true);

		//Artifacts dropped -- filename|md5
		$files = array();
		// TODO what about stored_modified_file ??
		$results = $parsedXml->xpath('/analysis/processes/process/stored_files/stored_created_file');
		foreach ($results as $result) {
			$arrayItemKey = '';
			$arrayItemValue = '';
			foreach ($result[0]->attributes() as $key => $val) {
				if ($key == 'filename') $arrayItemKey = (string)$val;
				if ($key == 'md5') $arrayItemValue = (string)$val;
				if ($key == 'filesize') $arrayItemSize = $val;
			}
			//$files[$arrayItemKey] = $arrayItemValue;
			if ($arrayItemSize > 0) {
				$files[] = array('key' => $arrayItemKey, 'val' => $arrayItemValue);
			}
		}
		//$files = array_unique($files);
		// write content..
		foreach ($files as $file) {
			$keyName = $file['key'];
			if (!strpos($file['key'], $realMalware)) {
				$itsType = 'malware-sample';
			} else {
				$itsType = 'filename|md5';
			}

			// the actual files..
			// seek $val in dirs and add..
			$ext = substr($file['key'], strrpos($file['key'], '.'));
			$actualFileName = $file['val'] . $ext;
			$actualFileNameBase = str_replace('\\', '/', $file['key']);
			$actualFileNameArray[] = basename($actualFileNameBase);
			$tempExplode = explode('\\', $file['key']);
			$realFileName = end($tempExplode);
			// have the filename, now look at parents parent for the process number
			$express = "/analysis/processes/process/stored_files/stored_created_file[@md5='" . $file['val'] . "']/../..";
			$results = $parsedXml->xpath($express);
			foreach ($results as $result) {
				foreach ($result[0]->attributes() as $key => $val) {
					if ((string)$key == 'index') $index = (string)$val;
				}
			}
			$actualFile = $rootDir . DS . 'Analysis' . DS . 'proc_' . $index . DS . 'modified_files' . DS . $actualFileName;
			$extraPath = 'Analysis' . DS . 'proc_' . $index . DS . 'modified_files' . DS;
			$file = new File($actualFile);
			if ($file->exists()) { // TODO put in array for test later
				$this->Event->Attribute->uploadAttachment($actualFile, $realFileName, true, $id, null, $extraPath, $keyName, $dist, true); // TODO was false
			} else {
			}
		}

		//Network activity -- ip-dst
		$ips = array();
		$hostnames = array();
		$results = $parsedXml->xpath('/analysis/processes/process/networkpacket_section/connect_to_computer');
		foreach ($results as $result) {
			foreach ($result[0]->attributes() as $key => $val) {
				if ($key == 'remote_ip') $ips[] = (string)$val;
				if ($key == 'remote_hostname') $hostnames[] = (string)$val;
			}
		}
		// write content..
		// ip-s
		foreach ($ips as $ip) {
			// add attribute..
			$this->Attribute->create();
			$this->Attribute->save(array(
					'event_id' => $id,
					'category' => 'Network activity',
					'type' => 'ip-dst',
					'value' => $ip,
					'to_ids' => false,
					'distribution' => $dist,
					'comment' => 'GFI import',
					));
		}
		foreach ($hostnames as $hostname) {
			// add attribute..
			$this->Attribute->create();
			$this->Attribute->save(array(
					'event_id' => $id,
					'category' => 'Network activity',
					'type' => 'hostname',
					'value' => $hostname,
					'to_ids' => false,
					'distribution' => $dist,
					'comment' => 'GFI import',
			));
		}
		// Persistence mechanism -- regkey|value
		$regs = array();
		$results = $parsedXml->xpath('/analysis/processes/process/registry_section/set_value');
		foreach ($results as $result) {
			$arrayItemKey = '';
			$arrayItemValue = '';
			foreach ($result[0]->attributes() as $key => $val) {
				if ($key == 'key_name') $arrayItemKey = (string)$val;
				if ($key == 'data') $arrayItemValue = (string)$val;
			}
			$regs[$arrayItemKey] = str_replace('(UNICODE_0x00000000)', '', $arrayItemValue);
		}
		//$regs = array_unique($regs);

		// write content..
		foreach ($regs as $key => $val) {
			// add attribute..
			$this->Attribute->create();

			if ($this->strposarray($val,$actualFileNameArray)) {
				$this->Attribute->save(array(
					'event_id' => $id,
					'comment' => 'GFI import',
					'category' => 'Persistence mechanism', // 'Persistence mechanism'
					'type' => 'regkey|value',
					'value' => $key . '|' . $val,
					'distribution' => $dist,
					'to_ids' => false
				));
			}
		}
	}

	public function strposarray($string, $array) {
		$toReturn = false;
		foreach ($array as $item) {
			if (strpos($string,$item)) {
				$toReturn = true;
			}
		}
		return $toReturn;
	}

	public function downloadSearchResult() {
		$idList = $this->Session->read('search_find_idlist');
		$this->Session->write('search_find_idlist', '');
		// display the full xml
		$this->response->type('xml');	// set the content type
		$this->layout = 'xml/default';
		$this->header('Content-Disposition: download; filename="misp.search.results.xml"');

		$results = $this->__fetchEvent(null, $idList);
		// Whitelist check
		$this->loadModel('Whitelist');
		$results = $this->Whitelist->removeWhitelistedFromArray($results, false);

		$this->set('results', $results);
		$this->render('xml');
	}

	// Use the rest interface to search for  attributes or events. Usage:
	// MISP-base-url/events/restSearch/[api-key]/[value]/[type]/[category]/[orgc]
	// value, type, category, orgc are optional
	// target can be either "event" or "attribute"
	// the last 4 fields accept the following operators:
	// && - you can use && between two search values to put a logical OR between them. for value, 1.1.1.1&&2.2.2.2 would find attributes with the value being either of the two.
	// ! - you can negate a search term. For example: google.com&&!mail would search for all attributes with value google.com but not ones that include mail. www.google.com would get returned, mail.google.com wouldn't.
	public function restSearch($key=null, $value=null, $type=null, $category=null, $org=null, $tags = '') {
		if ($value === 'null') $value = null;
		if ($type === 'null') $type = null;
		if ($category === 'null') $category = null;
		if ($org === 'null') $org = null;
		if ($key!=null && $key!='download') {
			$user = $this->checkAuthUser($key);
		} else {
			if (!$this->Auth->user()) throw new UnauthorizedException('You are not authorized. Please send the Authorization header with your auth key along with an Accept header for application/xml.');
			$user = $this->checkAuthUser($this->Auth->user('authkey'));
		}
		if (!$user) {
			throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
		}
		$value = str_replace('|', '/', $value);
		$this->response->type('xml');	// set the content type
		$this->layout = 'xml/default';
		$this->header('Content-Disposition: download; filename="misp.search.events.results.xml"');
		$conditions['AND'] = array();
		$subcondition = array();
		$this->loadModel('Attribute');
		// add the values as specified in the 2nd parameter to the conditions
		$values = explode('&&', $value);
		$parameters = array('value', 'type', 'category', 'org');
		foreach ($parameters as $k => $param) {
			if (isset(${$parameters[$k]})) {
				$elements = explode('&&', ${$parameters[$k]});
				foreach($elements as $v) {
					if (substr($v, 0, 1) == '!') {
						if ($parameters[$k] === 'value' && preg_match('@^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$@', substr($v, 1))) {
							$cidrresults = $this->Cidr->CIDR(substr($v, 1));
							foreach ($cidrresults as $result) {
								$subcondition['AND'][] = array('Attribute.value NOT LIKE' => $result);
							}
						} else {
							if ($parameters[$k] === 'org') {
								$subcondition['AND'][] = array('Event.' . $parameters[$k] . ' NOT LIKE' => '%'.substr($v, 1).'%');
							} else {
								$subcondition['AND'][] = array('Attribute.' . $parameters[$k] . ' NOT LIKE' => '%'.substr($v, 1).'%');
							}
						}
					} else {
						if ($parameters[$k] === 'value' && preg_match('@^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$@', substr($v, 1))) {
							$cidrresults = $this->Cidr->CIDR($v);
							foreach ($cidrresults as $result) {
								$subcondition['OR'][] = array('Attribute.value LIKE' => $result);
							}
						} else {
							if ($parameters[$k] === 'org') {
								$subcondition['OR'][] = array('Event.' . $parameters[$k] . ' LIKE' => '%'.$v.'%');
							} else {
								$subcondition['OR'][] = array('Attribute.' . $parameters[$k] . ' LIKE' => '%'.$v.'%');
							}
						}
					}
				}
				array_push ($conditions['AND'], $subcondition);
				$subcondition = array();
			}
		}

		// If we are looking for an attribute, we want to retrieve some extra data about the event to be able to check for the permissions.

		if (!$user['User']['siteAdmin']) {
			$temp = array();
			$temp['AND'] = array('Event.distribution >' => 0, 'Attribute.distribution >' => 0);
			$subcondition['OR'][] = $temp;
			$subcondition['OR'][] = array('Event.org' => $user['User']['org']);
			array_push($conditions['AND'], $subcondition);
		}

		// If we sent any tags along, load the associated tag names for each attribute
		if ($tags !== '') {
			$args = $this->Event->Attribute->dissectArgs($tags);
			$this->loadModel('Tag');
			$tagArray = $this->Tag->fetchEventTagIds($args[0], $args[1]);
			$temp = array();
			foreach ($tagArray[0] as $accepted) {
				$temp['OR'][] = array('Event.id' => $accepted);
			}
			$conditions['AND'][] = $temp;
			$temp = array();
			foreach ($tagArray[1] as $rejected) {
				$temp['AND'][] = array('Event.id !=' => $rejected);
			}
			$conditions['AND'][] = $temp;
		}

		$params = array(
			'conditions' => $conditions,
			'fields' => array('Attribute.event_id'),
		);
		$attributes = $this->Attribute->find('all', $params);
		$eventIds = array();
		foreach ($attributes as $attribute) {
			if (!in_array($attribute['Attribute']['event_id'], $eventIds)) $eventIds[] = $attribute['Attribute']['event_id'];
		}
		if (!empty($eventIds)) {
			$results = $this->__fetchEvent(null, $eventIds, $user['User']['org'], true);
		} else {
			throw new NotFoundException('No matches.');
		}
		$this->loadModel('Whitelist');
		$results = $this->Whitelist->removeWhitelistedFromArray($results, true);
		$this->response->type('xml');
		$this->set('results', $results);
	}

	public function downloadOpenIOCEvent($eventid) {

		// return a downloadable text file called misp.openIOC.<eventId>.ioc for individual events
		// TODO implement mass download of all events - maybe in a zip file?
		$this->response->type('text');	// set the content type
		if ($eventid == null) {
			throw new Exception('Not yet implemented');
			// $this->header('Content-Disposition: download; filename="misp.openIOC.ioc"');
		} else {
			$this->header('Content-Disposition: download; filename="misp.openIOC' . $eventid . '.ioc"');
		}
		$this->layout = 'text/default';

		// get the event if it exists and load it together with its attributes
		$this->Event->id = $eventid;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}
        if(!$this->_isInMySharingGroup($eventid)){
            throw new UnauthorizedException('You do not have the permission to view this event.');
        }
		$this->Event->contain('Attribute');
		$event = $this->Event->read(null, $eventid);
		foreach ($event['Attribute'] as $k => $attribute) {
			if (!$attribute['to_ids']) unset($event['Attribute'][$k]);
		}
		$this->loadModel('Whitelist');
		$temp = $this->Whitelist->removeWhitelistedFromArray(array($event), false);
		$event = $temp[0];
		//$event['Attribute'] = $this->Whitelist->removeWhitelistedFromArray($event['Attribute'], false);
		// set up helper variables for the authorisation check in the component
		$isMyEvent = false;
		if ($this->Auth->User('org') == $event['Event']['org']) $isMyEvent = true;
		$isSiteAdmin = $this->_isSiteAdmin();

		// send the event and the vars needed to check authorisation to the Component
		$final = $this->IOCExport->buildAll($event, $isMyEvent, $isSiteAdmin);
		$this->set('final', $final);
	}

	public function create_dummy_event() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException('You don\'t have the privileges to access this.');
		$date = new DateTime();
		$data['Event']['info'] = 'Test event showing every category-type combination';
		$data['Event']['date'] = '2013-10-09';
		$data['Event']['threat_level_id'] = 4; //'Undefined'
		$data['Event']['analysis'] = '0';
		$data['Event']['distribution'] = '0';

		$defaultValues = array(
				'md5' => '098f6bcd4621d373cade4e832627b4f6',
				'sha1' => 'a7645200866fd00bde529733ceac8506ab1f5518',
				'sha256' => '0f58957831a9cf0b768451ee6b236555f519c04f0da5a5ea87538fd0990b29d1',
				'filename' => 'test.exe',
				'filename|md5' => 'test.exe|8886be8e4e862189a68d27e8fc7a6144',
				'filename|sha1' => 'test.exe|a7645200866fd00bde529733ceac8506ab1f5518',
				'filename|sha256' => 'test.exe|0f58957831a9cf0b768451ee6b236555f519c04f0da5a5ea87538fd0990b29d1',
				'ip-src' => '1.1.1.1',
				'ip-dst' => '2.2.2.2',
				'hostname' => 'www.futuremark.com',
				'domain' => 'evildomain.org',
				'email-src' => 'bla@bla.com',
				'email-dst' => 'hmm@hmm.com',
				'email-subject' => 'Some made-up email subject',
				'email-attachment' => 'filename.exe',
				'url' => 'http://www.evilsite.com/test',
				'http-method' => 'POST',
				'user-agent' => 'Microsoft Internet Explorer',
				'regkey' => 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run\fishy',
				'regkey|value' => 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run\fishy|%ProgramFiles%\Malicios\malware.exe',
				'AS' => '45566',
				'snort' => 'alert ip 1.1.1.1 any -> $HOME_NET any (msg: "MISP e1 Incoming From IP: 1.1.1.1"; classtype:trojan-activity; sid:21; rev:1; priority:1; reference:url,http://localhost:8888/events/view/1;)',
				'pattern-in-file' => 'Somestringinfile',
				'pattern-in-traffic' => 'Somestringintraffic',
				'pattern-in-memory' => 'Somestringinmemory',
				'yara' => 'rule silent_banker : banker{meta:description = "This is just an example" thread_level = 3 in_the_wild = true strings: $a = {6A 40 68 00 30 00 00 6A 14 8D 91} $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9} $c = "UVODFRYSIHLNWPEJXQZAKCBGMT" condition:}',
				'vulnerability' => 'CVE-2011-0001',
				'attachment' => 'file.txt',
				'malware-sample' => 'test.exe|8886be8e4e862189a68d27e8fc7a6144',
				'link' => 'http://www.somesite.com/',
				'comment' => 'Comment',
				'text' => 'Any text',
				'other' => 'Could be anything',
				'named pipe' => '\\.\pipe\PipeName',
				'mutex' => 'mutexstring',
		);
		$this->loadModel('Attribute');
		foreach ($this->Attribute->categoryDefinitions as $category => $v) {
			foreach ($v['types'] as $k => $type) {
				$data['Attribute'][] = array(
					'category' => $category,
					'type' => $type,
					'value' => $defaultValues[$type],
					'to_ids' => '0',
					'distribution' => '0',
				);
			}
		}
		$this->Event->_add($data, false, $this->Auth->user());
	}

	public function proposalEventIndex() {
		$this->loadModel('ShadowAttribute');
		$this->ShadowAttribute->recursive = -1;
		$result = $this->ShadowAttribute->find('all', array(
				'fields' => array('event_id'),
				'group' => 'event_id',
				'conditions' => array(
						'ShadowAttribute.event_org =' => $this->Auth->user('org'),
				)));
		$this->Event->recursive = -1;
		$conditions = array();
		foreach ($result as $eventId) {
				$conditions['OR'][] = array('Event.id =' => $eventId['ShadowAttribute']['event_id']);
		}
		if (empty($result)) {
			$conditions['OR'][] = array('Event.id =' => -1);
		}
		$this->paginate = array(
				'fields' => array('Event.id', 'Event.org', 'Event.orgc', 'Event.timestamp', 'Event.distribution', 'Event.info', 'Event.date', 'Event.published'),
				'conditions' => $conditions,
				'contain' => array(
					'User' => array(
							'fields' => array(
								'User.email'
					)),
					'ShadowAttribute'=> array(
						'fields' => array(
							'ShadowAttribute.id', 'ShadowAttribute.org', 'ShadowAttribute.event_id'
						),
					),
		));
		$events = $this->paginate();
		foreach ($events as $k => $event) {
			$orgs = array();
			foreach ($event['ShadowAttribute'] as $sa) {
				if (!in_array($sa['org'], $orgs)) $orgs[] = $sa['org'];
			}
			$events[$k]['orgArray'] = $orgs;
		}
		$this->set('events', $events);
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
		$this->set('distributionLevels', $this->Event->distributionLevels);
	}

	private function __setHeaderForAdd($eventId) {
		$this->response->header('Location', Configure::read('MISP.baseurl') . '/events/' . $eventId);
		$this->response->send();
	}

	public function reportValidationIssuesEvents() {
		// search for validation problems in the events
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$results = $this->Event->reportValidationIssuesEvents();
		$result = $results[0];
		$count = $results[1];
		$this->set('result', $result);
		$this->set('count', $count);
	}


	public function generateLocked() {
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$toBeUpdated = $this->Event->generateLocked();
		$this->Session->setFlash('Events updated, '. $toBeUpdated . ' record(s) altered.');
		$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
	}

	public function generateThreatLevelFromRisk() {
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$updated = $this->Event->generateThreatLevelFromRisk();
		$this->Session->setFlash('Events updated, '. $updated . ' record(s) altered.');
		$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
	}

	public function addTag() {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		$tag_id = $this->request->data['Event']['tag'];
		$id = $this->request->data['Event']['id'];
		$this->Event->recurisve = -1;
		$event = $this->Event->read(array('id', 'org', 'orgc'), $id);
		// org should allow to tag too, so that an event that gets pushed can be tagged locally by the owning org
		if ($this->Auth->user('org') !== $event['Event']['org'] && $this->Auth->user('org') !== $event['Event']['orgc'] && !$this->_isSiteAdmin()) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		$this->Event->EventTag->Tag->id = $tag_id;
		if(!$this->Event->EventTag->Tag->exists()) {
			throw NotFoundException('Invalid tag.');
		}
		$found = $this->Event->EventTag->find('first', array(
			'conditions' => array(
				'event_id' => $id,
				'tag_id' => $tag_id
			),
			'recursive' => -1,
		));
		if (!empty($found)) {
			$this->Session->setFlash('Tag already assigned to this event.');
			$this->redirect(array('action' => 'view', $id));
		}
		$this->Event->EventTag->create();
		$this->Event->EventTag->save(array('event_id' => $id, 'tag_id' => $tag_id));
		$this->Session->setFlash('Tag added.');
		$this->redirect(array('action' => 'view', $id));
	}

	public function removeTag($id, $tag_id) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		$this->Event->recurisve = -1;
		$event = $this->Event->read(array('id', 'org', 'orgc'), $id);
		// org should allow to tag too, so that an event that gets pushed can be tagged locally by the owning org
		if ($this->Auth->user('org') !== $event['Event']['org'] && $this->Auth->user('org') !== $event['Event']['orgc'] && !$this->_isSiteAdmin()) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		$eventTag = $this->Event->EventTag->find('first', array(
			'conditions' => array(
				'event_id' => $id,
				'tag_id' => $tag_id
			),
			'recursive' => -1,
		));
		if (empty($eventTag)) throw new NotFoundException('Invalid event - tag combination.');
		$this->Event->EventTag->delete($eventTag['EventTag']['id']);
		$this->Session->setFlash('Tag removed.');
		$this->redirect(array('action' => 'view', $id));
	}
}
