<?php
App::uses('AppModel', 'Model');
/**
 * Server Model
 *
 */
class Server extends AppModel {

	public $name = 'Server';					// TODO general

	public $actsAs = array('SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable, check: 'userModel' and 'userKey' can be removed given default
		'userModel' => 'User',
		'userKey' => 'user_id',
		'change' => 'full'
	), 'Trim');

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'url';

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'url' => array( // TODO add extra validation to refuse multiple time the same url from the same org
			'url' => array(
				'rule' => array('url'),
				'message' => 'Please enter a valid base-url.',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			)
		),
		'authkey' => array(
			'minlength' => array(
				'rule' => array('minlength', 40),
				'message' => 'A authkey of a minimum length of 40 is required.',
				'required' => true,
			),
			'notempty' => array(
				'rule' => array('notempty'),
				'message' => 'Please enter a valid authentication key.',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'org' => array(
			'notempty' => array(
				'rule' => array('notempty'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'push' => array(
			'boolean' => array(
				'rule' => array('boolean'),
				//'message' => 'Your custom message here',
				'allowEmpty' => true,
				'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'pull' => array(
			'boolean' => array(
				'rule' => array('boolean'),
				//'message' => 'Your custom message here',
				'allowEmpty' => true,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'lastpushedid' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				'allowEmpty' => true,
				'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'lastpulledid' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				'allowEmpty' => true,
				'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
	);

	public function isOwnedByOrg($serverid, $org) {
		return $this->field('id', array('id' => $serverid, 'org' => $org)) === $serverid;
	}
	
	public function pull($user, $id = null, $technique=false, $server, $jobId = false) {
		$eventModel = ClassRegistry::init('Event');
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->read(null, $jobId);
		}
		App::uses('HttpSocket', 'Network/Http');
		$eventIds = array();
		if ("full" == $technique) {
			// get a list of the event_ids on the server
			$eventIds = $eventModel->getEventIdsFromServer($server);
			// FIXME this is not clean at all ! needs to be refactored with try catch error handling/communication
			if ($eventIds === 403) {
				return 1;
			} else if (is_string($eventIds)) {
				return 2;
			}
		
			// reverse array of events, to first get the old ones, and then the new ones
			$eventIds = array_reverse($eventIds);
			$eventCount = count($eventIds);
		} elseif ("incremental" == $technique) {
			// TODO incremental pull
			return 3;
		
		} elseif (true == $technique) {
			$eventIds[] = intval($technique);
		} else {
			return 4;
		}
		// now process the $eventIds to pull each of the events sequentially
		if (!empty($eventIds)) {
			$successes = array();
			$fails = array();
			$pulledProposals = array();
			// download each event
			if (null != $eventIds) {
				$HttpSocket = new HttpSocket();
				foreach ($eventIds as $k => &$eventId) {
					$event = $eventModel->downloadEventFromServer(
							$eventId,
							$server);
					if (null != $event) {
						// we have an Event array
						// The event came from a pull, so it should be locked.
						$event['Event']['locked'] = true;
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
										// if community falseonly, downgrade to org only after pull
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
						$event['Event']['user_id'] = $user['id'];
						// check if the event already exist (using the uuid)
						$existingEvent = null;
						$existingEvent = $eventModel->find('first', array('conditions' => array('Event.uuid' => $event['Event']['uuid'])));
						if (!$existingEvent) {
							// add data for newly imported events
							$passAlong = $server['Server']['url'];
							$result = $eventModel->_add($event, $fromXml = true, $user, $server['Server']['organization'], $passAlong, true);
							if ($result) $successes[] = $eventId;
							else {
								$fails[$eventId] = 'Failed (partially?) because of validation errors: '. print_r($eventModel->validationErrors, true);
							}
						} else {
							$result = $eventModel->_edit($event, $existingEvent['Event']['id']);
							if ($result === 'success') $successes[] = $eventId;
							else $fails[$eventId] = $result;
						}
					} else {
						// error
						$fails[$eventId] = 'failed downloading the event';
					}
					if ($jobId && $k%10 == 0) {
						$job->saveField('progress', $k * 100 / $eventCount);
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
				$this->save($event, array('fieldList' => array('lastpulledid', 'url')));
				// grab all of the shadow attributes that are relevant to us
		
				$events = $eventModel->find('all', array(
						'fields' => array('id', 'uuid'),
						'recursive' => -1,
				));
				$shadowAttribute = ClassRegistry::init('ShadowAttribute');
				$shadowAttribute->recursive = -1;
				foreach ($events as &$event) {
					$proposals = $eventModel->downloadEventFromServer($event['Event']['uuid'], $server, null, true);
					if (null != $proposals) {
						if (isset($proposals['ShadowAttribute']['id'])) {
							$temp = $proposals['ShadowAttribute'];
							$proposals['ShadowAttribute'] = array(0 => $temp);
						}
						foreach($proposals['ShadowAttribute'] as &$proposal) {
							unset($proposal['id']);
							$proposal['event_id'] = $event['Event']['id'];
							if (!$shadowAttribute->findByUuid($proposal['uuid'])) {
								if (isset($pulledProposals[$event['Event']['id']])) {
									$pulledProposals[$event['Event']['id']]++;
								} else {
									$pulledProposals[$event['Event']['id']] = 1;
								}
								$shadowAttribute->create();
								$shadowAttribute->save($proposal);
							}
						}
					}
				}
			}
		}
		return array($successes, $fails, $pulledProposals, $lastpulledid);
	}
	
	public function push($id = null, $technique=false, $jobId = false, $HttpSocket) {
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->read(null, $jobId);
		}
		$eventModel = ClassRegistry::init('Event');
		$this->read(null, $id);
		if ("full" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = 0;
		} elseif ("incremental" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = $this->data['Server']['lastpushedid'];
		} elseif (true == $technique) {
			$eventIds[] = array('Event' => array ('id' => intval($technique)));
		} else {
			$this->redirect(array('action' => 'index'));
		}
		if (!isset($eventIds)) {
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
			$eventIds = $eventModel->find('all', $findParams);
		}
		$eventCount = count($eventIds);
		//debug($eventIds);
		// now process the $eventIds to pull each of the events sequentially
		if (!empty($eventIds)) {
			$successes = array();
			$fails = array();
			$lowestfailedid = null;
			foreach ($eventIds as $k => $eventId) {
				$eventModel->recursive=1;
				$event = $eventModel->findById($eventId['Event']['id']);
				$event['Event']['locked'] = true;
				unset($event['User']);
				$result = $eventModel->uploadEventToServer(
						$event,
						$this->data,
						$HttpSocket);
				if ('Success' === $result) {
					$successes[] = $event['Event']['id'];
				} else {
					$fails[$event['Event']['id']] = $result;
				}
				if ($jobId && $k%10 == 0) {
					$job->saveField('progress', $k * 100 / $eventCount);
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
			// Save the entire Server data instead of just a single field, so that the logger can be fed with the extra fields.
			$this->data['Server']['lastpushedid'] = $lastpushedid;
			$this->save($this->data);
		}
		if (!isset($successes)) $successes = null;
		if (!isset($fails)) $fails = null;
		if ($jobId) {
			$temp = 'Fails: ';
			$failCount = count($fails);
			foreach ($fails as $k => $fail) {
				if ($k < $failCount) {
					$temp .= $fail . ', ';
				} else {
					$temp .= $fail;
				}
			}
			$job->saveField('message', $temp);
			return array($temp);
		} else {
			return array($successes, $fails);
		}
	}
}
