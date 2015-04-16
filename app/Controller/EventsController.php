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
		$this->Auth->allow('csv');
		$this->Auth->allow('nids');
		$this->Auth->allow('hids_md5');
		$this->Auth->allow('hids_sha1');
		$this->Auth->allow('text');
		$this->Auth->allow('dot');
		$this->Auth->allow('restSearch');
		$this->Auth->allow('stix');

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
						"AND" => array(
								array('Event.distribution >' => 0),
								Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
							)
						)
					)
				)
			);
		}
	}
	
	private function __filterOnAttributeValue($value) {
		// dissect the value
		$pieces = explode('|', $value);
		$test = array();
		$include = array();
		$exclude = array();
		$includeIDs = array();
		$excludeIDs = array();
		foreach ($pieces as $piece) {
			if ($piece[0] == '!') {
				$exclude[] =  '%' . strtolower(substr($piece, 1)) . '%';
			} else {
				$include[] = '%' . strtolower($piece) . '%';
			}
		}
		if (!empty($include)) {
			// get all of the attributes that should be included
			$includeQuery = array(
					'recursive' => -1,
					'fields' => array('id', 'event_id', 'distribution', 'value1', 'value2'),
					'conditions' => array(),
			);
			foreach ($include as $i) {
				$includeQuery['conditions']['OR'][] = array('lower(Attribute.value1) LIKE' => $i);
				$includeQuery['conditions']['OR'][] = array('lower(Attribute.value2) LIKE' => $i);
			}
			$includeHits = $this->Event->Attribute->find('all', $includeQuery);
			
			// convert it into an array that uses the event ID as a key
	
			foreach ($includeHits as $iH) {
				$includeIDs[$iH['Attribute']['event_id']][] = array('attribute_id' => $iH['Attribute']['id'], 'distribution' => $iH['Attribute']['distribution']);
			}
		}
		
		if (!empty($exclude)) {
			// get all of the attributes that should be excluded
			$excludeQuery = array(
				'recursive' => -1,
				'fields' => array('id', 'event_id', 'distribution', 'value1', 'value2'),
				'conditions' => array(),
			);
			foreach ($exclude as $e) {
				$excludeQuery['conditions']['OR'][] = array('lower(Attribute.value1) LIKE' => $e);
				$excludeQuery['conditions']['OR'][] = array('lower(Attribute.value2) LIKE' => $e);
			}
			$excludeHits = $this->Event->Attribute->find('all', $excludeQuery);
			
			// convert it into an array that uses the event ID as a key
			foreach ($excludeHits as $eH) {
				$excludeIDs[$eH['Attribute']['event_id']][] = array('attribute_id' => $eH['Attribute']['id'], 'distribution' => $eH['Attribute']['distribution']);
			}
		}
		if (!empty($exclude) || !empty($include)) {
		// if we are not site admin, fetch all of the events so that we can remove everything that the user is not allowed to see
			if (!$this->_isSiteAdmin()) {
				$eventQuery = array(
					'fields' => array('id', 'distribution', 'org'),
					'recursive' => -1,
					'conditions' => array(),
				);
				foreach ($excludeIDs as $eIK => $eIV) {
					$eventQuery['conditions']['OR'][] = array('Event.id' => $eIK);
				}
				foreach ($includeIDs as $iIK => $iIV) {
					$eventQuery['conditions']['OR'][] = array('Event.id' => $iIK);
				}
				$events = $this->Event->find('all', $eventQuery);
				foreach ($events as $e) {
					if ($e['Event']['org'] != $this->Auth->user('org')) {
						if ($e['Event']['distribution'] == 0) {
							// unset all attribute hits that include this event
							if (isset($includeIDs[$e['Event']['id']])) unset($includeIDs[$e['Event']['id']]);
							if (isset($excludeIDs[$e['Event']['id']])) unset($excludeIDs[$e['Event']['id']]);
						} else {
							// if the event has distribution > 0 but it doesn't belong to the current user then 
							// we still have to remove the attributes that have the distribution set lower.
							if (isset($includeIDs[$e['Event']['id']])) {
								foreach ($includeIDs[$e['Event']['id']] as $i => $iI) {
									if ($iI['distribution'] == 0) unset($includeIDs[$e['Event']['id']][$i]);
								}
							}
							if (isset($excludeIDs[$e['Event']['id']])) {
								foreach ($excludeIDs[$e['Event']['id']] as $i => $iI) {
									if ($iI['distribution'] == 0) unset($excludeIDs[$e['Event']['id']][$i]);
								}
							}
						}
					}
				}
			}
		}
		$includeIDs = array_keys($includeIDs);
		$excludeIDs = array_keys($excludeIDs);
		// return -1 as the only value in includedIDs if both arrays are empty. This will mean that no events will be shown if there was no hit
		if (empty($includeIDs) && empty($excludeIDs)) $includeIDs[] = -1;
		return array($includeIDs, $excludeIDs);
	}
	
	private function __quickFilter($value) {
		$result = array();
		
		// get all of the attributes that have a hit on the search term, in either the value or the comment field
		// This is not perfect, the search will be case insensitive, but value1 and value 2 are searched separately. lower() doesn't seem to work on virtualfields
		$attributeHits = $this->Event->Attribute->find('all', array(
				'recursive' => -1,
				'fields' => array('event_id', 'comment', 'distribution', 'value1', 'value2'),
				'conditions' => array(
					'OR' => array(
						'lower(value1) LIKE' => '%' . strtolower($value) . '%',
						'lower(value2) LIKE' => '%' . strtolower($value) . '%',
						'lower(comment) LIKE' => '%' . strtolower($value) . '%',
					),
				),
		));
		// rearrange the data into an array where the keys are the event IDs
		$eventsWithAttributeHits = array();
		foreach ($attributeHits as $aH) {
			$eventsWithAttributeHits[$aH['Attribute']['event_id']][] = $aH['Attribute'];
		}
		
		// Using the keys from the previously obtained ordered array, let's fetch all of the events involved
		$events = $this->Event->find('all', array(
				'recursive' => -1,
				'fields' => array('id', 'distribution', 'org'),
				'conditions' => array('id' => array_keys($eventsWithAttributeHits)),
		));
		
		// The problem with the above list is, that the user may still not be allowed to know about some of those attributes, 
		// or the events that contain them. Let's prune the list of events if the user is not a site admin.
		if (!$this->_isSiteAdmin()) {
			foreach ($events as $k => $event) {
				// if the event is not the user's org's event and is org only, unset it
				if ($event['Event']['distribution'] == 0 && $event['Event']['org'] != $this->Auth->user('org')) unset($events[$k]);
				else {
					// If the event doesn't belong to the user's org but the distribution is higher than 0, then the attributes still need to be checked
					if ($event['Event']['org'] != $this->Auth->user('org')) {
						$canKeep = false;
						foreach($eventsWithAttributeHits[$event['Event']['id']] as $att) {
							if ($att['distribution'] > 0) {
								$canKeep = true;
								break;
							}
						} 
						// if $canKeep is still false then we didn't find any matching attributes that the current user could see - unset the event :(
						if (!$canKeep) unset($events[$k]);
					}
				}
			}
		}
		foreach ($events as $event) {
			$result[] = $event['Event']['id'];
		}
		
		// we now have a list of event IDs that match on an attribute level, and the user can see it. Let's also find all of the events that match on other criteria!
		// What is interesting here is that we no longer have to worry about the event's releasability. With attributes this was a different case,
		// because we might run into a situation where a user can see an event but not a specific attribute
		// returning a hit on such an attribute would allow users to enumerate hidden attributes
		// For anything beyond this point the default pagination restrictions will apply!

		// First of all, there are tags that might be interesting for us
		$tags = $this->Event->EventTag->Tag->find('all', array(
				'conditions' => array('lower(name) LIKE' => '%' . strtolower($value) . '%'),
				'fields' => array('name', 'id'),
				'contain' => array('EventTag'),
		));
		foreach ($tags as $tag) {
			foreach ($tag['EventTag'] as $eventTag) {
				if (!in_array($eventTag['event_id'], $result)) $result[] = $eventTag['event_id'];
			}
		}

		// Finally, let's search on the event metadata!
		
		$otherEvents = $this->Event->find('all', array(
				'recursive' => -1,
				'fields' => array('id', 'orgc', 'info'),
				'conditions' => array(
					'OR' => array(
						'lower(orgc) LIKE' => '%' . strtolower($value) .'%',
						'lower(info) LIKE' => '%' . strtolower($value) .'%',
					),
				),
		));
		foreach ($otherEvents as $oE) {
			if (!in_array($oE['Event']['id'], $result)) $result[] = $oE['Event']['id'];
		}
		return $result;
	}

	/**
	 * index method
	 *
	 * @return void
	 */
	public function index() {
		// list the events
		$passedArgsArray = array();
		$urlparams = "";
		$this->set('passedArgs', json_encode($this->passedArgs));
		// check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
		foreach ($this->passedArgs as $k => $v) {
			if (substr($k, 0, 6) === 'search') {
				if ($urlparams != "") $urlparams .= "/"; 
				$urlparams .= $k . ":" . $v;
				$searchTerm = substr($k, 6);
				switch ($searchTerm) {
					case 'all' :
						$this->paginate['conditions']['AND'][] = array('Event.id' => $this->__quickFilter($this->passedArgs['searchall']));
						break;
					case 'attribute' :
						$event_id_arrays = $this->__filterOnAttributeValue($v);
						foreach ($event_id_arrays[0] as $event_id) $this->paginate['conditions']['AND']['OR'][] = array('Event.id' => $event_id);
						foreach ($event_id_arrays[1] as $event_id) $this->paginate['conditions']['AND'][] = array('Event.id !=' => $event_id);
						break;
					case 'published' :
						if ($v == 2) continue 2;
						$this->paginate['conditions']['AND'][] = array('Event.' . substr($k, 6) . ' =' => $v);
						break;
					case 'Datefrom' :
						if ($v == "") continue 2;
						$this->paginate['conditions']['AND'][] = array('Event.date >=' => $v);
						break;
					case 'Dateuntil' :
						if ($v == "") continue 2;
						$this->paginate['conditions']['AND'][] = array('Event.date <=' => $v);
						break;
					case 'org' :
						if ($v == "") continue 2;
						if (!Configure::read('MISP.showorg')) continue 2;
						// if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
						$pieces = explode('|', $v);
						$test = array();
						foreach ($pieces as $piece) {
							if ($piece[0] == '!') {
								$this->paginate['conditions']['AND'][] = array('lower(Event.orgc)' . ' NOT LIKE' => '%' . strtolower(substr($piece, 1)) . '%');
							} else {
								$test['OR'][] = array('lower(Event.orgc)' . ' LIKE' => '%' . strtolower($piece) . '%');
							}
						}
						$this->paginate['conditions']['AND'][] = $test;
						break;
					case 'eventinfo' :
						if ($v == "") continue 2;
						// if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
						$pieces = explode('|', $v);
						$test = array();
						foreach ($pieces as $piece) {
							if ($piece[0] == '!') {
								$this->paginate['conditions']['AND'][] = array('lower(Event.info)' . ' NOT LIKE' => '%' . strtolower(substr($piece, 1)) . '%');
							} else {
								$test['OR'][] = array('lower(Event.info)' . ' LIKE' => '%' . strtolower($piece) . '%');
							}
						}
						$this->paginate['conditions']['AND'][] = $test;
						break;
					case 'tag' :
						if (!$v || !Configure::read('MISP.tagging') || $v === 0) continue 2;
						$pieces = explode('|', $v);
						$filterString = "";
						foreach ($pieces as $piece) {
							if ($piece[0] == '!') {
								$block = $this->Event->EventTag->find('all', array(
										'conditions' => array('tag_id' => substr($piece, 1)),
										'fields' => 'event_id',
										'recursive' => -1,
								));
								foreach ($block as $b) {
									$this->paginate['conditions']['AND'][] = array('Event.id !=' => $b['EventTag']['event_id']);
								}
								$tagName = $this->Event->EventTag->Tag->find('first', array(
										'conditions' => array('id' => substr($piece, 1)),
										'fields' => array('id', 'name'),
										'recursive' => -1,
								));
								if ($filterString != "") $filterString .= "|";
								$filterString .= '!' . $tagName['Tag']['name'];
							} else {
								$allow = $this->Event->EventTag->find('all', array(
										'conditions' => array('tag_id' => $piece),
										'fields' => 'event_id',
										'recursive' => -1,
								));
								foreach ($allow as $a) {
									$this->paginate['conditions']['AND']['OR'][] = array('Event.id' => $a['EventTag']['event_id']);
								}
								$tagName = $this->Event->EventTag->Tag->find('first', array(
										'conditions' => array('id' => $piece),
										'fields' => array('id', 'name'),
										'recursive' => -1,
								));
								if ($filterString != "") $filterString .= "|";
								$filterString .= $tagName['Tag']['name'];
							}
						}
						$v = $filterString;
						break;
					case 'distribution' :
					case 'analysis' :
					case 'threatlevel' :
						if ($v == "") continue 2;
						$terms = array();
						$filterString = "";
						$searchTermInternal = $searchTerm;
						if ($searchTerm == 'threatlevel') {
							$searchTermInternal = 'threat_level_id';
							$threatLevels = $this->Event->ThreatLevel->find('all', array(
								'recursive' => -1,
								'fields' => array('id', 'name'),
							));
							foreach ($threatLevels as &$tl) $terms[$tl['ThreatLevel']['id']] =$tl['ThreatLevel']['name'];
						} else if ($searchTerm == 'analysis') {
							$terms = $this->Event->analysisLevels;
						} else {
							$terms = $this->Event->distributionLevels;
						}
						$pieces = explode('|', $v);
						$test = array();
						foreach ($pieces as $piece) {
							if ($filterString != "") $filterString .= '|';
							if ($piece[0] == '!') {
								$filterString .= $terms[substr($piece, 1)];
								$this->paginate['conditions']['AND'][] = array('Event.' . $searchTermInternal . ' !=' => substr($piece, 1));
							} else {
								$filterString .= $terms[$piece];
								$test['OR'][] = array('Event.' . $searchTermInternal => $piece);
							}
						}
						$this->paginate['conditions']['AND'][] = $test;
						$v = $filterString;
						break;
					default:
						if ($v == "") continue 2;
						$this->paginate['conditions'][] = array('lower(Event.' . substr($k, 6) . ') LIKE' => '%' . $v . '%');
						break;
				}
				$passedArgsArray[$searchTerm] = $v;
			}
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
		$this->set('urlparams', $urlparams);
		$this->set('passedArgsArray', $passedArgsArray);
		$this->paginate = Set::merge($this->paginate, array('contain' => array(
			'ThreatLevel' => array(
				'fields' => array(
					'ThreatLevel.name'))
			),
		));
		// for rest, don't use the pagination. With this, we'll escape the limit of events shown on the index.
		if ($this->_isRest()) {
			$rules = array();
			$fieldNames = array_keys($this->Event->getColumnTypes());
			$directions = array('ASC', 'DESC');
			if (isset($this->passedArgs['sort']) && in_array($this->passedArgs['sort'], $fieldNames)) {
				if (isset($this->passedArgs['direction']) && in_array(strtoupper($this->passedArgs['direction']), $directions)) {
					$rules['order'] = array($this->passedArgs['sort'] => $this->passedArgs['direction']);
				} else {
					$rules['order'] = array($this->passedArgs['sort'] => 'ASC');
				}
			} else {
				$rules['order'] = array('Event.id' => 'DESC');
			}
			if (isset($this->passedArgs['limit'])) {
				$rules['limit'] = intval($this->passedArgs['limit']);
			}
			$rules['contain'] = $this->paginate['contain'];
			if (isset($this->paginate['conditions'])) $rules['conditions'] = $this->paginate['conditions'];
			$events = $this->Event->find('all', $rules);
			$this->set('events', $events);
		} else {
			$this->set('events', $this->paginate());
		}
		
		if (!$this->Event->User->getPGP($this->Auth->user('id')) && Configure::read('GnuPG.onlyencrypted')) {
			$this->Session->setFlash(__('No GPG key set in your profile. To receive emails, submit your public key in your profile.'));
		}
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
		$this->set('distributionLevels', $this->Event->distributionLevels);
		$shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All');
		$this->set('shortDist', $shortDist);
	}
	
	public function filterEventIndex() {
		$passedArgsArray = array();
		
		$filtering = array(
			'published' => 2,
			'org' => array('OR' => array(), 'NOT' => array()),
			'tag' => array('OR' => array(), 'NOT' => array()),
			'date' => array('from' => "", 'until' => ""),
			'eventinfo' => array('OR' => array(), 'NOT' => array()),
			'threatlevel' => array('OR' => array(), 'NOT' => array()),
			'distribution' => array('OR' => array(), 'NOT' => array()),
			'analysis' => array('OR' => array(), 'NOT' => array()),
			'attribute' => array('OR' => array(), 'NOT' => array()),
		);

		foreach ($this->passedArgs as $k => $v) {
			if (substr($k, 0, 6) === 'search') {
				$searchTerm = substr($k, 6);
				switch ($searchTerm) {
					case 'published' :
						$filtering['published'] = $v;
						break;
					case 'Datefrom' :
						$filtering['date']['from'] = $v;
						break;
					case 'Dateuntil' :
						$filtering['date']['until'] = $v;
						break;
					case 'org' :
					case 'tag' :
					case 'eventinfo' :
					case 'attribute' :
					case 'threatlevel' :
					case 'distribution' :
					case 'analysis' :
						if ($v == "") continue 2;
						
						$pieces = explode('|', $v);
						foreach ($pieces as $piece) {
							if ($piece[0] == '!') {
								$filtering[$searchTerm]['NOT'][] = substr($piece, 1);
							} else {
								$filtering[$searchTerm]['OR'][] = $piece;
							}
						}
						break;
				}
				$passedArgsArray[$searchTerm] = $v;
			}
		}
		$this->set('filtering', json_encode($filtering));
		$tags = $this->Event->EventTag->Tag->find('all', array('recursive' => -1));
		$tagNames = array();
		$tagJSON = array();
		foreach ($tags as $k => $v) {
			$tagNames[$v['Tag']['id']] = $v['Tag']['name'];
			$tagJSON[] = array('id' => $v['Tag']['id'], 'value' => $v['Tag']['name']);
		}
		$conditions = array();
		if (!$this->_isSiteAdmin()) {
			$conditions = array('OR' => array(array('orgc' => $this->Auth->User('org')), array('distribution >' => 0)));
		}
		$events = $this->Event->find('all', array(
			'recursive' => -1,
			'fields' => array('orgc', 'distribution'),
			'conditions' => $conditions,
			'group' => 'orgc'
		));
		$rules = array('published', 'tag', 'date', 'eventinfo', 'threatlevel', 'distribution', 'analysis', 'attribute');
		if (Configure::read('MISP.showorg')){
			$orgs = array();
			foreach ($events as $e) {
				$orgs[] = $e['Event']['orgc'];
			}
			$orgs = $this->_arrayToValuesIndexArray($orgs);
			$this->set('showorg', true);
			$this->set('orgs', $orgs);
			$rules[] = 'org';
		} else {
			$this->set('showorg', false);
		}
		$rules = $this->_arrayToValuesIndexArray($rules);
		$this->set('tags', $tagNames);
		$this->set('tagJSON', json_encode($tagJSON));
		$this->set('rules', $rules);
		$this->set('baseurl', Configure::read('MISP.baseurl'));
		$this->layout = 'ajax';
	}
	
	/**
	 * view method
	 *
	 * @param int $id
	 * @return void
	 * @throws NotFoundException
	 */

	public function view($id = null, $continue=false, $fromEvent=null) {
		if (isset($this->params['named']['attributesPage'])) $page = $this->params['named']['attributesPage'];
		else {
			if ($this->_isRest()) {
				$page = 'all';
			} else {
				$page = 1;
			}
		}
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
			'conditions' => array('model' => 'ShadowAttribute', 'org !=' => $results[0]['Event']['orgc'], 'title LIKE' => '%Event (' . $id . ')%'),
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
		
		if (!$this->_isRest()) {
			// modify event for attribute pagination
			$eventArray = array();
			$shadowAttributeTemp = array();
			foreach ($this->Attribute->validate['category']['rule'][1] as $category) {
				foreach ($result['Attribute'] as $attribute) {
					if ($attribute['category'] == $category) {
						$shadowAttributeTemp = $attribute['ShadowAttribute'];
						$attribute['ShadowAttribute'] = null;
						$attribute['objectType'] = 0;
						$attribute['hasChildren'] = 0;
						$eventArray[] = $attribute; 
						$current = count($eventArray)-1;
						foreach ($shadowAttributeTemp as $k => $shadowAttribute) {
							$shadowAttribute['objectType'] = 1;
							if ($k == 0) $shadowAttribute['firstChild'] = true;
							if (($k + 1) == count($shadowAttributeTemp)) $shadowAttribute['lastChild'] = true;
							$eventArray[] = $shadowAttribute;
							$eventArray[$current]['hasChildren'] = 1;
						}
					}
				}
			}
			foreach ($result['ShadowAttribute'] as $shadowAttribute) {
				$shadowAttribute['objectType'] = 2;
				$eventArray[] = $shadowAttribute;
			}
			$this->set('objectCount', count($eventArray));
			if ($page == 'all') $this->set('eventArray', $eventArray);
			else {
				$this->set('eventArray', array_splice($eventArray, (($page-1)*50), 50));
			}
		}
		
		if(isset($result['ShadowAttribute'])) {
			$this->set('remaining', $result['ShadowAttribute']);
		}
		$this->set('relatedEvents', $result['RelatedEvent']);

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
			
			// set the types + categories for the attribute add/edit ajax overlays
			$categories = $this->Attribute->validate['category']['rule'][1];
			array_pop($categories);
			$categories = $this->_arrayToValuesIndexArray($categories);
			$this->set('categories', compact('categories'));
			
			$types = array_keys($this->Attribute->typeDefinitions);
			$types = $this->_arrayToValuesIndexArray($types);
			$this->set('types', $types);
			$this->set('categoryDefinitions', $this->Event->Attribute->categoryDefinitions);
			$typeCategory = array();
			foreach ($this->Attribute->categoryDefinitions as $k => $category) {
				foreach ($category['types'] as $type) {
					$typeCategory[$type][] = $k;
				}
			}
			$this->set('typeCategory', $typeCategory);
			$this->request->data['Attribute']['event_id'] = $id;
			
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
			if (!$this->_isSiteAdmin()) {
				foreach ($posts as &$post) {
					if ($post['User']['org'] != $this->Auth->user('org')) {
						$post['User']['email'] = 'User ' . $post['User']['id'] . ' (' . $post['User']['org'] . ')';
					}
				}
			}
			// Show the discussion
			$this->set('posts', $posts);
			$this->set('thread_id', $thread['Thread']['id']);
			$this->set('myuserid', $this->Auth->user('id'));
			$this->set('thread_title', $thread['Thread']['title']);
			if ($this->request->is('ajax')) {
				$this->disableCache();
				$this->layout = 'ajax';
				if (!isset($this->params['named']['attributesPage'])) {
					$this->render('/Elements/eventdiscussion');
				} else {
					$this->set('page', $this->params['named']['attributesPage']);
					$this->render('/Elements/eventattribute');
				}
			} else {
				$this->set('page', $page);
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
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException('You don\'t have permissions to create events');
		}
		if ($this->request->is('post')) {
			if ($this->_isRest()) {
				
				// rearrange the response if the event came from an export
				if(isset($this->request->data['response'])) $this->request->data = $this->request->data['response'];
				
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
					if ($this->_isRest()) $this->request->data = $this->Event->updateXMLArray($this->request->data, false);
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
								throw new NotFoundException('Event already exists, if you would like to edit it, use the url in the location header.');
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
				if (isset($this->data['Event']['submittedxml'])) {
					if (Configure::read('MISP.take_ownership_xml_import') 
						&& (isset($this->data['Event']['takeownership']) && $this->data['Event']['takeownership'] == 1)) {
						$this->_addXMLFile(true);
					} else {
						$this->_addXMLFile();
					}
				}

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
			'atomic' => true));
		// FIXME chri: check if output of $saveResult is what we expect when data not valid, see issue #104
		if ($saveResult) {
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
				if ($this->_isRest()) {
					if (isset($this->request->data['response'])) $this->request->data = $this->Event->updateXMLArray($this->request->data, true);
					else $this->request->data = $this->Event->updateXMLArray($this->request->data, false);
				}
				// Workaround for different structure in XML/array than what CakePHP expects
				if (isset($this->request->data['response'])) $this->request->data = $this->request->data['response'];
				$this->request->data = $this->Event->cleanupEventArrayFromXML($this->request->data);
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
								|| ($this->userRole['perm_sync'] && $existingEvent['Event']['locked']) || $this->_isSiteAdmin()) {
							// Only allow an edit if this is true!
							$saveEvent = true;
						} else throw new MethodNotAllowedException('Event could not be saved: The user used to edit the event is not authorised to do so. This can be caused by the user not being of the same organisation as the original creator of the event whilst also not being a site administrator.');
					} else throw new MethodNotAllowedException('Event could not be saved: No timestamp on the pushed edit or event in the request not newer than the local copy.');
				} else throw new MethodNotAllowedException('Event could not be saved: Could not find the local event.');
				$fieldList = array(
						'Event' => array('date', 'threat_level_id', 'analysis', 'info', 'published', 'uuid', 'from', 'distribution', 'timestamp'),
						'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'revision', 'distribution', 'timestamp', 'comment'),
						'ShadowAttribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'org', 'event_org', 'comment', 'event_uuid', 'deleted', 'to_ids', 'uuid')
				);

				$c = 0;
				if (isset($this->request->data['Attribute'])) {
					foreach ($this->request->data['Attribute'] as $attribute) {
						if (isset($attribute['uuid'])) {
							$existingAttribute = $this->Event->Attribute->findByUuid($attribute['uuid']);
							if (count($existingAttribute)) {
								$this->request->data['Attribute'][$c]['id'] = $existingAttribute['Attribute']['id'];
								// Check if the attribute's timestamp is bigger than the one that already exists.
								// If yes, it means that it's newer, so insert it. If no, it means that it's the same attribute or older - don't insert it, insert the old attribute.
								// Alternatively, we could unset this attribute from the request, but that could lead with issues if we decide that we want to start deleting attributes that don't exist in a pushed event.
								if ($this->request->data['Attribute'][$c]['timestamp'] > $existingAttribute['Attribute']['timestamp']) {
	
								} else {
									unset($this->request->data['Attribute'][$c]);
									//$this->request->data['Attribute'][$c] = $existingAttribute['Attribute'];
								}
							}
						}
						$c++;
					}
				}
				
				// check if the exact proposal exists, if yes check if the incoming one is deleted or not. If it is deleted, remove the old proposal and replace it with the one marked for being deleted
				// otherwise throw the new one away.
				if (isset($this->request->data['ShadowAttribute'])) {
					foreach ($this->request->data['ShadowAttribute'] as $k => &$proposal) {
						$existingProposal = $this->Event->ShadowAttribute->find('first', array(
							'recursive' => -1,
							'conditions' => array(
								'value' => $proposal['value'],
								'category' => $proposal['category'],
								'to_ids' => $proposal['to_ids'],
								'type' => $proposal['type'],
								'event_uuid' => $proposal['event_uuid'],
								'uuid' => $proposal['uuid']
							)
						));
						if ($existingProposal['ShadowAttribute']['deleted'] == 1) {
							$this->Event->ShadowAttribute->delete($existingProposal['ShadowAttribute']['id'], false);
						} else {
							unset($this->request->data['ShadowAttribute'][$k]);
						}
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

		// find the uuid
		$result = $this->Event->findById($id);
		$uuid = $result['Event']['uuid'];
		
		if (!$this->_isSiteAdmin()) {
			$this->Event->read();
			if ($this->Event->data['Event']['orgc'] != $this->_checkOrg()) {
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
					$this->Session->setFlash(__(sprintf('Event published but not pushed to %s, re-try later. If the issue persists, make sure that the correct sync user credentials are used for the server link and that the sync user on the remote server has authentication privileges.', $resultString), true));
				}
			} else {
				// update the DB to set the published flag
				// for background jobs, this should be done already
				$fieldList = array('published', 'id', 'info', 'publish_timestamp');
				$event['Event']['published'] = 1;
				$event['Event']['publish_timestamp'] = time();
				$this->Event->save($event, array('fieldList' => $fieldList));
				$this->Session->setFlash(__('Job queued.'));
			}
			$this->redirect(array('action' => 'view', $id));
		} else {
			$this->set('id', $id);
			$this->set('type', 'publish');
			$this->render('ajax/eventPublishConfirmationForm');
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
					if (Configure::read('MISP.background_jobs')) {
						$this->Session->setFlash(__('Job queued.', true));
					} else {
						$this->Session->setFlash(__('Email sent to all participants.', true));
					}
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
		} else {
			$this->set('id', $id);
			$this->set('type', 'alert');
			$this->render('ajax/eventPublishConfirmationForm');
		}
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
			$user = $this->Auth->user();
			$user['gpgkey'] = $this->Event->User->getPGP($user['id']);
			if ($this->Event->sendContactEmailRouter($id, $message, $all, $user, $this->_isSiteAdmin())) {
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

	public function xml($key, $eventid=null, $withAttachment = false, $tags = false, $from = false, $to = false) {
		App::uses('XMLConverterTool', 'Tools');
		$converter = new XMLConverterTool();
		$this->loadModel('Whitelist');
		
		// request handler for POSTed queries. If the request is a post, the parameters (apart from the key) will be ignored and replaced by the terms defined in the posted xml object.
		// The correct format for a posted xml is a "request" root element, as shown by the examples below:
		// For XML: <request><value>7.7.7.7&amp;&amp;1.1.1.1</value><type>ip-src</type></request>
		if ($this->request->is('post')) {
			if (empty($this->request->data)) {
				throw new BadRequestException('Either specify the search terms in the url, or POST an xml (with the root element being "request".');
			} else {
				$data = $this->request->data;
			}
			$paramArray = array('eventid', 'withAttachment', 'tags', 'from', 'to');
			foreach ($paramArray as $p) {
				if (isset($data['request'][$p])) ${$p} = $data['request'][$p];
				else ${$p} = null;
			}
		}
		
		$simpleFalse = array('tags', 'eventid', 'withAttachment', 'from', 'to');
		foreach ($simpleFalse as $sF) {
			if (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false') ${$sF} = false;
		}
		if ($tags) $tags = str_replace(';', ':', $tags);
		
		$eventIdArray = array();
		
		if ($eventid) {
			if (!is_numeric($eventid)) throw new MethodNotAllowedException('Invalid Event ID.');
			$eventIdArray[] = $eventid;
		}
		
		if ($key != 'download') {
			// check if the key is valid -> search for users based on key
			$user = $this->checkAuthUser($key);
			if (!$user) {
				throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
			}
			$org = $user['User']['org'];
			$isSiteAdmin = $user['User']['siteAdmin'];
		} else {
			if (!$this->Auth->user('id')) {
				throw new UnauthorizedException('You have to be logged in to do that.');
			}
			$org = $this->Auth->user('org');
			$isSiteAdmin = $this->_isSiteAdmin();
		}
		
		if ($eventid) {
			$final_filename='misp.event' . $eventid . '.export.xml';
		} else {
			$final_filename='misp.export.xml';
		}
		$final = "";
		$final .= '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL . '<response>' . PHP_EOL;
		
		if (!$eventid) {
			$events = $this->Event->fetchEventIds($org, $isSiteAdmin, $from, $to);
			foreach ($events as $event) $eventIdArray[] = $event['Event']['id'];
		}
		
		foreach ($eventIdArray as $currentEventId) {
			$result = $this->__fetchEvent($currentEventId, null, $org, $isSiteAdmin, $tags, $from, $to);
			if ($withAttachment) {
				foreach ($result[0]['Attribute'] as &$attribute) {
					if ($this->Event->Attribute->typeIsAttachment($attribute['type'])) {
						$encodedFile = $this->Event->Attribute->base64EncodeAttachment($attribute);
						$attribute['data'] = $encodedFile;
					}
				}
			}
			$result = $this->Whitelist->removeWhitelistedFromArray($result, false);
			$final .= $converter->event2XML($result[0]) . PHP_EOL;
		}
		$final .= '</response>' . PHP_EOL;
		$this->response->body($final);
		$this->response->type('xml');
		$this->response->download($final_filename);
		return $this->response;
	}

	// Grab an event or a list of events for the event view or any of the XML exports. The returned object includes an array of events (or an array that only includes a single event if an ID was given)
	// Included with the event are the attached attributes, shadow attributes, related events, related attribute information for the event view and the creating user's email address where appropriate
	private function __fetchEvent($eventid = false, $idList = false, $orgFromFetch = false, $isSiteAdmin = false, $tags = false, $from=false, $to=false) {
		// if we come from automation, we may not be logged in - instead we used an auth key in the URL.
		if (!empty($orgFromFetch)) {
			$org = $orgFromFetch;
		} else {
			$org = $this->_checkOrg();
			$isSiteAdmin = $this->_isSiteAdmin();
		}
		$results = $this->Event->fetchEvent($eventid, $idList, $org, $isSiteAdmin, null, $tags, $from, $to);
		return $results;
	}

	public function nids($format = 'suricata', $key = 'download', $id = false, $continue = false, $tags = false, $from = false, $to = false) {
		$simpleFalse = array('id', 'continue', 'tags', 'from', 'to');
		foreach ($simpleFalse as $sF) {
			if (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false') ${$sF} = false;
		}
		if ($tags) $tags = str_replace(';', ':', $tags);
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
			$user = array('User' => $this->Auth->user());
			$user['User']['siteAdmin'] = $this->_isSiteAdmin();
		}
		
		// display the full snort rulebase
		$this->loadModel('Attribute');
		$rules = $this->Attribute->nids($user['User']['siteAdmin'], $user['User']['org'], $format, $user['User']['nids_sid'], $id, $continue, $tags, $from, $to);
		$this->set('rules', $rules);
	}

	public function hids($type, $key='download', $tags = false, $from = false, $to = false) {
		$simpleFalse = array('tags', 'from', 'to');
		foreach ($simpleFalse as $sF) {
			if (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false') ${$sF} = false;
		}
		if ($tags) $tags = str_replace(';', ':', $tags);
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
			$user = array('User' => $this->Auth->user());
			$user['User']['siteAdmin'] = $this->_isSiteAdmin();
		}	
		$this->loadModel('Attribute');

		$rules = $this->Attribute->hids($user['User']['siteAdmin'], $user['User']['org'], $type, $tags, $from, $to);
		$this->set('rules', $rules);
	}
	// csv function
	// Usage: csv($key, $eventid)   - key can be a valid auth key or the string 'download'. Download requires the user to be logged in interactively and will generate a .csv file
	// $eventid can be one of 3 options: left empty it will get all the visible to_ids attributes,
	// $ignore is a flag that allows the export tool to ignore the ids flag. 0 = only IDS signatures, 1 = everything. 
	public function csv($key, $eventid=false, $ignore=false, $tags = false, $category=false, $type=false, $includeContext=false, $from=false, $to=false) {
		$simpleFalse = array('eventid', 'ignore', 'tags', 'category', 'type', 'includeContext', 'from', 'to');
		foreach ($simpleFalse as $sF) {
			if (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false') ${$sF} = false;
		}
		if ($tags) $tags = str_replace(';', ':', $tags);
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
			$ioc = $this->Session->read('paginate_conditions_ioc');
			$paginateConditions = $this->Session->read('paginate_conditions');
			$attributes = $this->Event->Attribute->find('all', array(
				'conditions' => $paginateConditions['conditions'],
				'contain' => $paginateConditions['contain'],
			));
			if ($ioc) {
				$this->loadModel('Whitelist');
				$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
			}
			$list = array();
			foreach ($attributes as &$attribute) {
				$list[] = $attribute['Attribute']['id'];
			}
		}
		$attributes = $this->Event->csv($org, $isSiteAdmin, $eventid, $ignore, $list, $tags, $category, $type, $includeContext, $from, $to);
		$this->loadModel('Whitelist');
		$final = array();
		$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
		foreach ($attributes as $attribute) {
			$line = $attribute['Attribute']['uuid'] . ',' . $attribute['Attribute']['event_id'] . ',' . $attribute['Attribute']['category'] . ',' . $attribute['Attribute']['type'] . ',' . $attribute['Attribute']['value'] . ',' . intval($attribute['Attribute']['to_ids']) . ',' . $attribute['Attribute']['timestamp'];
			if ($includeContext) {
				foreach($this->Event->csv_event_context_fields_to_fetch as $field => $header) {
					$line .= ',' . $attribute['Attribute'][$header];
				}
			}
			$final[] = $line;
		}
		
		$this->response->type('csv');	// set the content type
		if (!$eventid) {
			$this->header('Content-Disposition: download; filename="misp.all_attributes.csv"');
		} else if ($eventid === 'search') {
			$this->header('Content-Disposition: download; filename="misp.search_result.csv"');
		} else {
			$this->header('Content-Disposition: download; filename="misp.event_' . $eventid . '.csv"');
		}
		$this->layout = 'text/default';
		$headers = array('uuid', 'event_id', 'category', 'type', 'value', 'to_ids', 'date');
		if ($includeContext) $headers = array_merge($headers, array_values($this->Event->csv_event_context_fields_to_fetch));
		$this->set('headers', $headers);
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
			$fileData = fread(fopen($xml, "r"), filesize($xml));

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
			
			// add the original openIOC file as an attachment
			$saveEvent['Attribute'][] = array(
				'category' => 'External analysis',
				'uuid' =>  String::uuid(),
				'type' => 'attachment',
				'value' => $this->data['Event']['submittedioc']['name'],
				'to_ids' => false,
				'distribution' => $dist,
				'data' => base64_encode($fileData),
				'comment' => 'OpenIOC import source file'
			);

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

	public function _addXMLFile($take_ownership = false) {
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
					if ($take_ownership) $temp['Event']['orgc'] = $this->Auth->user('org');
					$this->Event->_add($temp, true, $this->Auth->user());
				}
			} else {
				$temp['Event'] = $xmlArray['response']['Event'];
				if ($take_ownership) $temp['Event']['orgc'] = $this->Auth->user('org');
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
		$ioc = $this->Session->read('paginate_conditions_ioc');
		$paginateConditions = $this->Session->read('paginate_conditions');
		$attributes = $this->Event->Attribute->find('all', array(
			'conditions' => $paginateConditions['conditions'],
			'contain' => $paginateConditions['contain'],
		));
		if ($ioc) {
			$this->loadModel('Whitelist');
			$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
		}
		$idList = array();
		foreach ($attributes as &$attribute) {
			if (!in_array($attribute['Attribute']['event_id'], $idList)) {
				$idList[] = $attribute['Attribute']['event_id'];
			}
		}
		// display the full xml
		$this->response->type('xml');	// set the content type
		$this->layout = 'xml/default';
		$this->header('Content-Disposition: download; filename="misp.search.results.xml"');

		$results = $this->__fetchEvent(null, $idList);

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
	public function restSearch($key='download', $value=false, $type=false, $category=false, $org=false, $tags = false, $searchall=false, $from=false, $to=false) {
		if ($key!='download') {
			$user = $this->checkAuthUser($key);
		} else {
			if (!$this->Auth->user()) throw new UnauthorizedException('You are not authorized. Please send the Authorization header with your auth key along with an Accept header for application/xml.');
			$user = $this->checkAuthUser($this->Auth->user('authkey'));
		}
		if (!$user) {
			throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
		}
		$value = str_replace('|', '/', $value);
		// request handler for POSTed queries. If the request is a post, the parameters (apart from the key) will be ignored and replaced by the terms defined in the posted json or xml object.
		// The correct format for both is a "request" root element, as shown by the examples below:
		// For Json: {"request":{"value": "7.7.7.7&&1.1.1.1","type":"ip-src"}}
		// For XML: <request><value>7.7.7.7&amp;&amp;1.1.1.1</value><type>ip-src</type></request>
		// the response type is used to determine the parsing method (xml/json)
		if ($this->request->is('post')) {
			if ($this->response->type() === 'application/json') {
				$data = $this->request->input('json_decode', true);
			} elseif ($this->response->type() === 'application/xml') {
				$data = $this->request->data;
			} else {
				throw new BadRequestException('Either specify the search terms in the url, or POST a json array / xml (with the root element being "request" and specify the correct headers based on content type.');
			}
			$paramArray = array('value', 'type', 'category', 'org', 'tags', 'searchall', 'from', 'to');
			foreach ($paramArray as $p) {
				if (isset($data['request'][$p])) ${$p} = $data['request'][$p];
				else ${$p} = null;
			}
		}
		
		$simpleFalse = array('value' , 'type', 'category', 'org', 'tags', 'searchall', 'from', 'to');
		foreach ($simpleFalse as $sF) {
			if (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false') ${$sF} = false;
		}
		if ($tags) $tags = str_replace(';', ':', $tags);
		if ($searchall === 'true') $searchall = "1";

		$conditions['AND'] = array();
		$subcondition = array();
		$this->loadModel('Attribute');
		// add the values as specified in the 2nd parameter to the conditions
		$values = explode('&&', $value);
		if (isset($searchall) && ($searchall == 1 || $searchall === true || $searchall == 'true')) {
			$eventIds = $this->__quickFilter($value);
		} else {
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
				$temp['AND'] = array(
							'Event.distribution >' => 0,
							'Attribute.distribution >' => 0,
							Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array()
						);
				$subcondition['OR'][] = $temp;
				$subcondition['OR'][] = array('Event.org' => $user['User']['org']);
				array_push($conditions['AND'], $subcondition);
			}
			
			// If we sent any tags along, load the associated tag names for each attribute
			if ($tags) {
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

			if ($from) $conditions['AND'][] = array('Event.date >=' => $from);
			if ($to) $conditions['AND'][] = array('Event.date <=' => $to);
			
			$params = array(
					'conditions' => $conditions,
					'fields' => array('DISTINCT(Attribute.event_id)'),
			);
			$attributes = $this->Attribute->find('all', $params);
			$eventIds = array();
			foreach ($attributes as $attribute) {
				if (!in_array($attribute['Attribute']['event_id'], $eventIds)) $eventIds[] = $attribute['Attribute']['event_id'];
			}
		}
		if (!empty($eventIds)) {
			$this->loadModel('Whitelist');
			if ((!isset($this->request->params['ext']) || $this->request->params['ext'] !== 'json') && $this->response->type() !== 'application/json') {
				App::uses('XMLConverterTool', 'Tools');
				$converter = new XMLConverterTool();
				$final = "";
				$final .= '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL . '<response>' . PHP_EOL;
				foreach ($eventIds as $currentEventId) {
					$result = $this->__fetchEvent($currentEventId, null, $user['User']['org'], true);
					$result = $this->Whitelist->removeWhitelistedFromArray($result, false);
					$final .= $converter->event2XML($result[0]) . PHP_EOL;
				}
				$final .= '</response>' . PHP_EOL;
				$final_filename="misp.search.events.results.xml";
				$this->response->body($final);
				$this->response->type('xml');
				$this->response->download($final_filename);
			} else {
				App::uses('JSONConverterTool', 'Tools');
				$converter = new JSONConverterTool();
				$temp = array();
				$final = '{"response":[';
				foreach ($eventIds as $k => $currentEventId) {
					$result = $this->__fetchEvent($currentEventId, null, $user['User']['org'], true);
					$final .= $converter->event2JSON($result[0]);
					if ($k < count($eventIds) -1 ) $final .= ',';
				}
				$final .= ']}';
				$final_filename="misp.search.events.results.json";
				$this->response->body($final);
				$this->response->type('json');
				$this->response->download($final_filename);
			}
		} else {
			throw new NotFoundException('No matches.');
		}
		return $this->response;
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
				'target-user' => 'user1',
				'target-email' => 'someone@something.com',
				'target-machine' => 'machinename',
				'target-org' => 'EA games',
				'target-location' => 'Hell',
				'target-external' => 'some target'
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
	
	// for load testing, it's slow, execution time is set at 1 hour maximum
	public function create_massive_dummy_events() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException('You don\'t have the privileges to access this.');
		ini_set('max_execution_time', 3600);
		$this->Event->Behaviors->unload('SysLogLogable.SysLogLogable');
		$date = new DateTime();
		$ts =  $date->getTimestamp();
		$default = array('Event' => array(
			'info' => 'A junk event for load testing',
			'date' => '2014-09-01',
			'threat_level_id' => 4,
			'distribution' => 0,
			'analysis' => 0,
			'org' => $this->Auth->user('org'),
			'orgc' => $this->Auth->user('org'),
			'timestamp' => $ts,	
			'uuid' => String::uuid(),
			'user_id' => $this->Auth->user('id'),
		));
		$default['Event']['info'] = 'A junk event for load testing';
		$default['Event']['date'] = '2013-10-09';
		$default['Event']['threat_level_id'] = 4; //'Undefined'
		$default['Event']['analysis'] = '0';
		$default['Event']['distribution'] = '0';
		for ($i = 0; $i < 50; $i++) {
			$data = $default;
			for ($j = 0; $j < 3000; $j++) {
				$value = mt_rand();
				$data['Attribute'][] = array(
						'category' => 'Other',
						'type' => 'text',
						'value' => $value,
						'to_ids' => '0',
						'distribution' => '0',
						'value1' => $value,
						'value2' => '',
						'comment' => '',
						'uuid' => String::uuid(),
						'timestamp' => $ts,
				);
			}
			$this->Event->create();
			$this->Event->saveAssociated($data, array('validate' => false));
		}
	}
	
	public function proposalEventIndex() {
		$this->loadModel('ShadowAttribute');
		$this->ShadowAttribute->recursive = -1;
		$conditions = array('ShadowAttribute.deleted' => 0);
		if (!$this->_isSiteAdmin()) $conditions[] = array('ShadowAttribute.event_org' => $this->Auth->user('org'));
		$result = $this->ShadowAttribute->find('all', array(
				'fields' => array('event_id'),
				'group' => 'event_id',
				'conditions' => $conditions
		));
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
						'conditions' => array(
							'ShadowAttribute.deleted' => 0
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
	
	public function addTag($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		$tag_id = $this->request->data['Event']['tag'];
		$id = $this->request->data['Event']['id'];
		$this->Event->recurisve = -1;
		$event = $this->Event->read(array('id', 'org', 'orgc', 'distribution'), $id);
		// org should allow to tag too, so that an event that gets pushed can be tagged locally by the owning org
		if (($this->Auth->user('org') !== $event['Event']['org'] && $this->Auth->user('org') !== $event['Event']['orgc'] && $event['Event']['distribution'] == 0) || (!$this->userRole['perm_tagger']) && !$this->_isSiteAdmin()) {
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
		$this->autoRender = false;
		if (!empty($found)) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Tag is already attached to this event.')), 'status'=>200));
			//$this->Session->setFlash('Tag already assigned to this event.');
			//$this->redirect(array('action' => 'view', $id));
		}
		$this->Event->EventTag->create();
		if ($this->Event->EventTag->save(array('event_id' => $id, 'tag_id' => $tag_id))) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Tag added.')), 'status'=>200));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Tag could not be added.')),'status'=>200));
		}
	}
	
	public function removeTag($id, $tag_id) {
		if (!$this->request->is('post') || !$this->request->is('ajax')) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		$this->Event->recurisve = -1;
		$event = $this->Event->read(array('id', 'org', 'orgc', 'distribution'), $id);
		// org should allow to tag too, so that an event that gets pushed can be tagged locally by the owning org
		if (($this->Auth->user('org') !== $event['Event']['org'] && $this->Auth->user('org') !== $event['Event']['orgc'] && $event['Event']['distribution'] == 0) || (!$this->userRole['perm_tagger']) && !$this->_isSiteAdmin()) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')),'status'=>200));
		}
		$eventTag = $this->Event->EventTag->find('first', array(
			'conditions' => array(
				'event_id' => $id,
				'tag_id' => $tag_id
			),
			'recursive' => -1,
		));
		$this->autoRender = false;
		if (empty($eventTag)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid event - tag combination.')),'status'=>200));
		if ($this->Event->EventTag->delete($eventTag['EventTag']['id'])) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Tag removed.')), 'status'=>200));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Tag could not be removed.')),'status'=>200));
		}
	}
	
	public function freeTextImport($id) {
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException('Event not found or you don\'t have permissions to create attributes');
		}
		$event = $this->Event->find('first', array(
				'conditions' => array('Event.id' => $id),
				'fields' => array('id', 'orgc'),
				'recursive' => -1
		));
		if (!$this->_isSiteAdmin() && !empty($event) && $event['Event']['orgc'] != $this->Auth->user('org')) throw new MethodNotAllowedException('Event not found or you don\'t have permissions to create attributes');
		$this->set('event_id', $id);
		if ($this->request->is('get')) {
			$this->layout = 'ajax';
			$this->request->data['Attribute']['event_id'] = $id;
		}
		
		if ($this->request->is('post')) {
			App::uses('ComplexTypeTool', 'Tools');
			$complexTypeTool = new ComplexTypeTool();
			$resultArray = $complexTypeTool->checkComplexRouter($this->request->data['Attribute']['value'], 'FreeText');
			foreach ($resultArray as &$r) {
				$temp = array();
				foreach ($r['types'] as $type) {
					$temp[$type] = $type;
				}
				$r['types'] = $temp;
			}
			$typeCategoryMapping = array();
			foreach ($this->Event->Attribute->categoryDefinitions as $k => $cat) {
				foreach ($cat['types'] as $type) {
					$typeCategoryMapping[$type][$k] = $k;
				}
			}
			$defaultCategories = array(
					'md5' => 'Payload delivery',
					'sha1' => 'Payload delivery',
					'sha256' => 'Payload delivery',
					'regkey' => 'Persistence mechanism',
					'filename' => 'Payload delivery',
					'ip-src' => 'Network activity',
					'ip-dst' => 'Network activity',
					'hostname' => 'Network activity',
					'domain' => 'Network activity',
					'url' => 'Network activity',
					'link' => 'Network activity',
					'email-src' => 'Payload delivery',
					'email-dst' => 'Payload delivery',
					'text' => 'Other',
			);
			$this->set('typeList', array_keys($this->Event->Attribute->typeDefinitions));
			$this->set('defaultCategories', $defaultCategories);
			$this->set('typeCategoryMapping', $typeCategoryMapping);
			$this->set('resultArray', $resultArray);
			$this->render('free_text_results');
		}
	}
	
	public function saveFreeText($id) {
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException('Event not found or you don\'t have permissions to create attributes');
		}
		if ($this->request->is('post')) {
			$event = $this->Event->find('first', array(
				'conditions' => array('id' => $id),
				'recursive' => -1,
				'fields' => array('orgc', 'id', 'distribution', 'published'),
			));
			if (!$this->_isSiteAdmin() && !empty($event) && $event['Event']['orgc'] != $this->Auth->user('org')) throw new MethodNotAllowedException('Event not found or you don\'t have permissions to create attributes');
			$saved = 0;
			$failed = 0;
			$attributes = json_decode($this->request->data['Attribute']['JsonObject'], true);
			foreach ($attributes as $k => $attribute) {
				if ($attribute['type'] == 'ip-src/ip-dst') {
					$types = array('ip-src', 'ip-dst');
				} else {
					$types = array($attribute['type']);
				}
				foreach ($types as $type) {
					$this->Event->Attribute->create();
					$attribute['type'] = $type;
					$attribute['distribution'] = $event['Event']['distribution'];
					if (empty($attribute['comment'])) $attribute['comment'] = 'Imported via the freetext import.';
					$attribute['event_id'] = $id;
					if ($this->Event->Attribute->save($attribute)) {
						$saved++;
					} else {
						$failed++;
					}
				}
			}
			if ($saved > 0) {
				$event = $this->Event->find('first', array(
						'conditions' => array('Event.id' => $id),
						'recursive' => -1
				));
				if ($event['Event']['published'] == 1) {
					$event['Event']['published'] = 0;
				}
				$date = new DateTime();
				$event['Event']['timestamp'] = $date->getTimestamp();
				$this->Event->save($event);
			}
			if ($failed > 0) {
				$this->Session->setFlash($saved . ' attributes created. ' . $failed . ' attributes could not be saved. This may be due to attributes with similar values already existing.');
			} else {
				$this->Session->setFlash($saved . ' attributes created.');
			}
			$this->redirect(array('controller' => 'events', 'action' => 'view', $id));
		} else {
			throw new MethodNotAllowedException();
		}
	}
	
	public function stix($key, $id = false, $withAttachments = false, $tags = false, $from = false, $to = false) {
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
		
		// request handler for POSTed queries. If the request is a post, the parameters (apart from the key) will be ignored and replaced by the terms defined in the posted xml object.
		// The correct format for a posted xml is a "request" root element, as shown by the examples below:
		// For XML: <request><id>!3&amp;!4</id><tags>OSINT</tags></request>
		// This would return all OSINT tagged events except for event #3 and #4
		if ($this->request->is('post')) {
			if (empty($this->request->data)) {
				throw new BadRequestException('Either specify the search terms in the url, or POST an xml (with the root element being "request".');
			} else {
				$data = $this->request->data;
			}
			$paramArray = array('id', 'withAttachment', 'tags', 'from', 'to');
			foreach ($paramArray as $p) {
				if (isset($data['request'][$p])) ${$p} = $data['request'][$p];
				else ${$p} = null;
			}
		}
		
		$simpleFalse = array('id', 'withAttachments', 'tags', 'from', 'to');
		foreach ($simpleFalse as $sF) {
			if (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false') ${$sF} = false;
		}
		
		// set null if a null string is passed
		$numeric = false;
		if (is_numeric($id)) $numeric = true;
		// set the export type based on the request
		if ($this->response->type() === 'application/json') $returnType = 'json';
		else {
			$returnType = 'xml';
			$this->response->type('xml');	// set the content type
			$this->layout = 'xml/default';
		}
		$result = $this->Event->stix($id, $tags, $withAttachments, $org, $isSiteAdmin, $returnType, $from, $to);
		
		if ($result['success'] == 1) {
			// read the output file and pass it to the view
			if (!$numeric) {
				$this->header('Content-Disposition: download; filename="misp.stix.event.collection.' . $returnType . '"');
			} else {
				$this->header('Content-Disposition: download; filename="misp.stix.event' . $id . '.' . $returnType . '"');
			}
			$this->set('data', $result['data']);
		} else {
			throw new Exception(h($result['message']));
		}
	}

	public function filterEventIdsForPush() {
		if (!$this->userRole['perm_sync']) throw new MethodNotAllowedException('You do not have the permission to do that.');
		if ($this->request->is('post')) {
			$incomingIDs = array();
			$incomingEvents = array();
			foreach ($this->request->data as $event) {
				$incomingIDs[] = $event['Event']['uuid'];
				$incomingEvents[$event['Event']['uuid']] = $event['Event']['timestamp'];
			}
			$events = $this->Event->find('all', array(
				'conditions' => array('Event.uuid' => $incomingIDs),
				'recursive' => -1,
				'fields' => array('Event.uuid', 'Event.timestamp', 'Event.locked'),
			));
			foreach ($events as $k => $v) {
				if ($v['Event']['timestamp'] >= $incomingEvents[$v['Event']['uuid']]) {
					unset($incomingEvents[$v['Event']['uuid']]);
					continue;
				}
				if ($v['Event']['locked'] == 0) {
					unset($incomingEvents[$v['Event']['uuid']]);
				}
			}
			$this->set('result', array_keys($incomingEvents));
		}
	}
	
	public function checkuuid($uuid) {
		if (!$this->userRole['perm_sync']) throw new MethodNotAllowedException('You do not have the permission to do that.');
		$events = $this->Event->find('first', array(
				'conditions' => array('Event.uuid' => $uuid),
				'recursive' => -1,
				'fields' => array('Event.uuid'),
		));
		$this->set('result', array('result' => empty($events)));
	}
	
	public function pushProposals($uuid) {
		$message= "";
		$success = true;
		$counter = 0;
		if (!$this->userRole['perm_sync']) throw new MethodNotAllowedException('You do not have the permission to do that.');
		if ($this->request->is('post')) {
			$event = $this->Event->find('first', array(
					'conditions' => array('Event.uuid' => $uuid),
					'contains' => array('ShadowAttribute', 'Attribute' => array(
						'fields' => array('id', 'uuid', 'event_id'),
					)),
					'fields' => array('Event.uuid', 'Event.id'),
			));
			if (empty($event)) {
				$message = "Event not found.";
				$success = false;
			} else {
				foreach ($this->request->data as $k => $sa) {
					if (isset($event['ShadowAttribute'])) {
						foreach ($event['ShadowAttribute'] as $oldk => $oldsa) {
							$temp = json_encode($oldsa);
							if ($sa['event_uuid'] == $oldsa['event_uuid'] && $sa['value'] == $oldsa['value'] && $sa['type'] == $oldsa['type'] && $sa['category'] == $oldsa['category'] && $sa['to_ids'] == $oldsa['to_ids']) {
								if ($oldsa['timestamp'] < $sa['timestamp']) $this->Event->ShadowAttribute->delete($oldsa['id']);
								else continue 2;
							}
						}
					}
					$sa['event_id'] = $event['Event']['id'];
					if ($sa['old_id'] != 0) {
						foreach($event['Attribute'] as $attribute) {
							if ($sa['uuid'] == $attribute['uuid']) {
								$sa['old_id'] = $attribute['id'];
							}
						}
					}
					if (isset($sa['id'])) unset($sa['id']);
					$this->Event->ShadowAttribute->create();
					if (!$this->Event->ShadowAttribute->save(array('ShadowAttribute' => $sa))) {
						$message = "Some of the proposals could not be saved.";
						$success = false;
					} else {
						$counter++;
					}
					//if (!$sa['deleted']) $this->Event->ShadowAttribute->__sendProposalAlertEmail($event['Event']['id']);
				}
			}
			if ($success) {
				if ($counter) {	
					$message = $counter . " Proposal(s) added.";
				} else {
					$message = "Nothing to update.";
				}
			}
			$this->set('data', array('success' => $success, 'message' => $message, 'counter' => $counter));
			$this->set('_serialize', 'data');
		}
	}
	
	public function exportChoice($id) {
		$event = $this->Event->find('first' ,array(
				'conditions' => array('id' => $id),
				'recursive' => -1,
				'fields' => array('distribution', 'orgc','id', 'published'),
		));
		if (empty($event) || (!$this->_isSiteAdmin() && $event['Event']['orgc'] != $this->Auth->user('org') && $event['Event']['distribution'] < 1)) throw new NotFoundException('Event not found or you are not authorised to view it.');
		$exports = array(
			'xml' => array(
					'url' => '/events/xml/download/' . $id,
					'text' => 'MISP XML (metadata + all attributes)',
					'requiresPublished' => false,
					'checkbox' => true,
					'checkbox_text' => 'Encode Attachments',
					'checkbox_set' => '/true'
			),
			'json' => array(
					'url' => '/events/view/' . $id . '.json',
					'text' => 'MISP JSON (metadata + all attributes)',
					'requiresPublished' => false,
					'checkbox' => false,
			),
			'openIOC' => array(
					'url' => '/events/downloadOpenIOCEvent/' . $id,
					'text' => 'OpenIOC (all indicators marked to IDS)',
					'requiresPublished' => true,
					'checkbox' => false,
			),
			'csv' => array(
					'url' => '/events/csv/download/' . $id . '/1',
					'text' => 'CSV',
					'requiresPublished' => true,
					'checkbox' => true,
					'checkbox_text' => 'Include non-IDS marked attributes',
					'checkbox_set' => '/1'
			),
			'stix_xml' => array(
					'url' => '/events/stix/download/' . $id . '.xml',
					'text' => 'STIX XML (metadata + all attributes)',
					'requiresPublished' => true,
					'checkbox' => true,
					'checkbox_text' => 'Encode Attachments',
					'checkbox_set' => '/true'
			),
			'stix_json' => array(
					'url' => '/events/stix/download/' . $id . '.json',
					'text' => 'STIX JSON (metadata + all attributes)',
					'requiresPublished' => true,
					'checkbox' => true,
					'checkbox_text' => 'Encode Attachments',
					'checkbox_set' => '/true'
			),
			'suricata' => array(
					'url' => '/events/nids/suricata/download/' . $id,
					'text' => 'Download Suricata rules',
					'requiresPublished' => true,
					'checkbox' => false,
			),
			'snort' => array(
					'url' => '/events/nids/snort/download/' . $id,
					'text' => 'Download Snort rules',
					'requiresPublished' => true,
					'checkbox' => false,
			),
			'text' => array(
					'url' => '/attributes/text/download/all/false/' . $id,
					'text' => 'Export all attribute values as a text file',
					'requiresPublished' => true,
					'checkbox' => true,
					'checkbox_text' => 'Include non-IDS marked attributes',
					'checkbox_set' => '/true'
			),
		);
		if ($event['Event']['published'] == 0) {
			foreach ($exports as $k => $export) {
				if ($export['requiresPublished']) unset($exports[$k]);	
			}
		}
		$this->set('exports', $exports);
		$this->set('id', $id);
		$this->render('ajax/exportChoice');
	}
}
