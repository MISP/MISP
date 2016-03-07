<?php
App::uses('AppModel', 'Model');

class Feed extends AppModel {

	public $actsAs = array('SysLogLogable.SysLogLogable' => array(
			'change' => 'full'
		), 
		'Trim',
		'Containable'
	);
	
/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'url' => array( // TODO add extra validation to refuse multiple time the same url from the same org
			'rule' => array('url'),
			'message' => 'Please enter a valid url.',
		),
		'provider' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'name' => array(
				'valueNotEmpty' => array(
						'rule' => array('valueNotEmpty'),
				),
		),
	);
	
	// gets the event UUIDs from the feed by ID
	// returns an array with the UUIDs of events that are new or that need updating
	public function getNewEventUuids($feed, $HttpSocket) {
		$result = array();
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/manifest.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) return 1;
		$manifest = json_decode($response->body, true);
		if (!$manifest) return 2;
		$this->Event = ClassRegistry::init('Event');
		$events = $this->Event->find('all', array(
			'conditions' => array(
				'Event.uuid' => array_keys($manifest),
			),
			'recursive' => -1,
			'fields' => array('Event.id', 'Event.uuid', 'Event.timestamp')
		));
		foreach ($events as &$event) {
			if ($event['Event']['timestamp'] < $manifest[$event['Event']['uuid']]['timestamp']) $result['edit'][] = array('uuid' => $event['Event']['uuid'], 'id' => $event['Event']['id']);
			unset($manifest[$event['Event']['uuid']]);
		}
		$result['add'] = array_keys($manifest);
		return $result;
	}
	
	
	public function getManifest($feed, $HttpSocket) {
		$result = array();
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/manifest.json';
		$response = $HttpSocket->get($uri, '', $request);
		try {
			$events = json_decode($response->body, true);
		} catch (Exception $e) {
			return false;
		}
		$events = $this->__filterEventsIndex($events, $feed);
		return $events;
	}
	
	public function downloadFromFeed($actions, $feed, $HttpSocket, $user) {
		$this->Event = ClassRegistry::init('Event');
		$results = array();
		$filterRules = false;
		if (isset($feed['Feed']['rules']) && !empty($feed['Feed']['rules'])) {
			$filterRules = json_decode($feed['Feed']['rules'], true);
		}
		if (isset($actions['add']) && !empty($actions['add'])) {
			foreach ($actions['add'] as $uuid) {
				$result = $this->__addEventFromFeed($HttpSocket, $feed, $uuid, $user, $filterRules);
				if ($result === 'blocked') debug('blocked: ' . $uuid);
				if ($result === true) {
					$results['add']['success'] = $uuid;
				} else {
					$results['add']['fail'] = array('uuid' => $uuid, 'reason' => $result);
				}
			}
		}
		if (isset($actions['edit']) && !empty($actions['edit'])) {
			foreach ($actions['edit'] as $editTarget) {
				$result = $this->__updateEventFromFeed($HttpSocket, $feed, $editTarget['uuid'], $editTarget['id'], $user, $filterRules);
				if ($result === true) {
					$results['edit']['success'] = $uuid;
				} else {
					$results['edit']['fail'] = array('uuid' => $uuid, 'reason' => $result);
				}
			}
		}
		throw new Exception();
		return $results;
	}
	
	private function __createFeedRequest() {
		$version = $this->checkMISPVersion();
		$version = implode('.', $version);
		return array(
			'header' => array(
					'Accept' => 'application/json',
					'Content-Type' => 'application/json',
					'MISP-version' => $version,
			)
		);
	}
	
	private function __checkIfEventBlockedByFilter($event, $filterRules) {
		$fields = array('tags' => 'Tag', 'orgs' => 'Orgc');
		$prefixes = array('OR', 'NOT');
		foreach ($fields as $field => $fieldModel) {
			foreach ($prefixes as $prefix) {
				if (!empty($filterRules[$field][$prefix])) {
					$found = false;
					if (isset($event['Event'][$fieldModel]) && !empty($event['Event'][$fieldModel])) {
						if (!isset($event['Event'][$fieldModel][0])) $event['Event'][$fieldModel] = array(0 => $event['Event'][$fieldModel]);
						foreach ($event['Event'][$fieldModel] as $object) {
							foreach ($filterRules[$field][$prefix] as $temp) {
								if (stripos($object['name'], $temp) !== false) $found = true;
							}
						}
					}
					if ($prefix === 'OR' && !$found) return false;
					if ($prefix !== 'OR' && $found) return false;
				}
			}
		}
		if (!$filterRules) return true;
		return true;
	}
	
	private function __filterEventsIndex($events, $feed) {
		$filterRules = array();
		if (isset($feed['Feed']['rules']) && !empty($feed['Feed']['rules'])) {
			$filterRules = json_decode($feed['Feed']['rules'], true);
		}
		foreach ($events as $k => &$event) {
			if (isset($filterRules['orgs']['OR']) && !empty($filterRules['orgs']['OR']) && !in_array($event['Orgc']['name'], $filterRules['orgs']['OR'])) {
				unset($events[$k]);
				continue;
			}
			if (isset($filterRules['orgs']['NO']) && !empty($filterRules['orgs']['NOT']) && in_array($event['Orgc']['name'], $filterRules['orgs']['OR'])) {
				unset($events[$k]);
				continue;
			}
			if (isset($filterRules['tags']['OR']) && !empty($filterRules['tags']['OR'])) {
				if (!isset($event['Tag']) || empty($event['Tag'])) unset($events[$k]);
				$found = false;
				foreach ($event['Tag'] as &$tag) {
					foreach ($filterRules['tags']['OR'] as $filterTag) if (strpos(strtolower($filterTag), $tag)) $found = true;
				}
				if (!$found) {
					unset($k);
					continue;
				}
			}
			if (isset($filterRules['tags']['NOT']) && !empty($filterRules['tags']['NOT'])) {
				if (isset($event['Tag']) && !empty($event['Tag'])) {
					$found = false;
					foreach ($event['Tag'] as &$tag) {
						foreach ($filterRules['tags']['NOT'] as $filterTag) if (strpos(strtolower($filterTag), $tag)) $found = true;
					}
					if ($found) {
						unset($k);
					}
				}
			}
		}
		return $events;
	}
	
	public function downloadEventFromFeed($feed, $uuid, $user) {
		$HttpSocket = $this->__setupHttpSocket($feed);
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/' . $uuid . '.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) {
			return false;
		} else {
			$filterRules = $this->__prepareFilterRules($feed);
			$event = $this->__prepareEvent($response->body, $filterRules);
			if ($event !== true) return $event;
			$this->Event = ClassRegistry::init('Event');
			return $this->Event->_add($event, true, $user);
		}
	}
	
	private function __prepareEvent($body, $filterRules) {
		$event = json_decode($body, true);
		if (isset($event['response'])) $event = $event['response'];
		if (isset($event[0])) $event = $event[0];
		if (!isset($event['Event']['uuid'])) return false;
		if (!$this->__checkIfEventBlockedByFilter($event, $filterRules)) return 'blocked';
		return $event;
	}
	
	private function __prepareFilterRules($feed) {
		$filterRules = false;
		if (isset($feed['Feed']['rules']) && !empty($feed['Feed']['rules'])) $filterRules = json_decode($feed['Feed']['rules'], true);
		return $filterRules;
	}
	
	private function __setupHttpSocket($feed) {
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		return ($syncTool->setupHttpSocketFeed($feed));
	}
	
	private function __addEventFromFeed($HttpSocket, $feed, $uuid, $user, $filterRules) {
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/' . $uuid . '.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) {
			return false;
		} else {
			$filterRules = $this->__prepareFilterRules($feed);
			$event = $this->__prepareEvent($response->body, $filterRules);
			$this->Event = ClassRegistry::init('Event');
			return $this->Event->_add($event, true, $user);
		}
	}
	
	private function __updateEventFromFeed($HttpSocket, $feed, $uuid, $eventId, $user, $filterRules) {
		debug($uuid);
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/' . $uuid . '.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) {
			return false;
		} else {
			$filterRules = $this->__prepareFilterRules($feed);
			$event = $this->__prepareEvent($response->body, $filterRules);
			$this->Event = ClassRegistry::init('Event');
			return $this->Event->_edit($event, $user, $uuid, $jobId = null);
		}
	}
	
}
