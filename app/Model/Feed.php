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
			if ($event['Event']['timestamp'] < $manifest[$event['Event']['uuid']]) $result['edit'][] = array('uuid' => $event['Event']['uuid'], 'id' => $event['Event']['id']);
			unset($manifest[$event['Event']['uuid']]);
		}
		$result['add'] = array_keys($manifest);
		return $result;
	}
	
	public function downloadFromFeed($actions, $feed, $HttpSocket, $user) {
		$this->Event = ClassRegistry::init('Event');
		if (isset($actions['add']) && !empty($actions['add'])) {
			foreach ($actions['add'] as $uuid) {
				$this->__addEventFromFeed($HttpSocket, $feed, $uuid, $user);
			}
		}
		if (isset($actions['edit']) && !empty($actions['edit'])) {
			foreach ($actions['edit'] as $editTarget) {
				$this->__updateEventFromFeed($HttpSocket, $feed, $editTarget['uuid'], $editTarget['id'], $user);
			}
		}
	}
	
	private function __createFeedRequest() {
		$version = $this->checkMISPVersion();
		$version = implode('.', $version);
		return array(
			'header' => array(
					'Accept' => 'application/json',
					'Content-Type' => 'application/json',
					'MISP-version' => $version
			)
		);
	}
	
	private function __addEventFromFeed($HttpSocket, $feed, $uuid, $user) {
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/' . $uuid . '.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) {
			return false;
		} else {
			$event = json_decode($response->body, true);
			if (isset($event['response'])) $event = $event['response'];
			if (isset($event[0])) $event = $event[0];
			if (!isset($event['Event']['uuid'])) return false;
			$this->Event = ClassRegistry::init('Event');
			return $this->Event->_add($event, true, $user);
		}
	}
	
	private function __updateEventFromFeed($HttpSocket, $feed, $uuid, $eventId, $user) {
		debug($uuid);
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/' . $uuid . '.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) {
			return false;
		} else {
			$event = json_decode($response->body, true);
			if (isset($event['response'])) $event = $event['response'];
			if (isset($event[0])) $event = $event[0];
			if (!isset($event['Event']['uuid'])) return false;
			$this->Event = ClassRegistry::init('Event');
			debug($this->Event->_edit($event, $user, $uuid, $jobId = null));
			//return $this->Event->_edit($event, $user, $uuid, $jobId = null);
		}
	}
	
}
