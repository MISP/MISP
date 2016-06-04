<?php
App::uses('AppModel', 'Model');

class Feed extends AppModel {

	public $actsAs = array('SysLogLogable.SysLogLogable' => array(
			'change' => 'full'
		),
		'Trim',
		'Containable'
	);

	public $belongsTo = array(
			'SharingGroup' => array(
					'className' => 'SharingGroup',
					'foreignKey' => 'sharing_group_id',
			),
			'Tag' => array(
					'className' => 'Tag',
					'foreignKey' => 'tag_id',
			)
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

	public function downloadFromFeed($actions, $feed, $HttpSocket, $user, $jobId = false) {
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->read(null, $jobId);
			$email = "Scheduled job";
		}
		$total = 0;
		if (isset($actions['add']) && !empty($actions['add'])) $total += count($actions['add']);
		if (isset($actions['edit']) && !empty($actions['edit'])) $total += count($actions['edit']);
		$currentItem = 0;
		$this->Event = ClassRegistry::init('Event');
		$results = array();
		$filterRules = false;
		if (isset($feed['Feed']['rules']) && !empty($feed['Feed']['rules'])) {
			$filterRules = json_decode($feed['Feed']['rules'], true);
		}
		if (isset($actions['add']) && !empty($actions['add'])) {
			foreach ($actions['add'] as $uuid) {
				$result = $this->__addEventFromFeed($HttpSocket, $feed, $uuid, $user, $filterRules);
				if ($result === 'blocked') continue;
				if ($result === true) {
					$results['add']['success'] = $uuid;
				} else {
					$results['add']['fail'] = array('uuid' => $uuid, 'reason' => $result);
				}
				if ($jobId) {
					$job->id = $jobId;
					$job->saveField('progress', 100 * (($currentItem + 1) / $total));
				}
				$currentItem++;
			}
		}
		if (isset($actions['edit']) && !empty($actions['edit'])) {
			foreach ($actions['edit'] as $editTarget) {
				$result = $this->__updateEventFromFeed($HttpSocket, $feed, $editTarget['uuid'], $editTarget['id'], $user, $filterRules);
				if ($result === 'blocked') continue;
				if ($result === true) {
					$results['edit']['success'] = $uuid;
				} else {
					$results['edit']['fail'] = array('uuid' => $uuid, 'reason' => $result);
				}
				if ($jobId && $currentItem % 10 == 0) {
					$job->id = $jobId;
					$job->saveField('progress', 100 * (($currentItem + 1) / $total));
				}
				$currentItem++;
			}
		}
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
					foreach ($filterRules['tags']['OR'] as $filterTag) {
						if (strpos(strtolower($tag['name']), strtolower($filterTag))) $found = true;
					}
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
						foreach ($filterRules['tags']['NOT'] as $filterTag) if (strpos(strtolower($tag['name']), strtolower($filterTag))) $found = true;
					}
					if ($found) {
						unset($k);
					}
				}
			}
		}
		return $events;
	}

	public function downloadAndSaveEventFromFeed($feed, $uuid, $user) {
		$event = $this->downloadEventFromFeed($feed, $uuid, $user);
		if (!is_array($event) || isset($event['code'])) return false;
		return $this->__saveEvent($event, $user);
	}

	public function downloadEventFromFeed($feed, $uuid, $user) {
		$HttpSocket = $this->__setupHttpSocket($feed);
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/' . $uuid . '.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) {
			return false;
		} else {
			return $this->__prepareEvent($response->body, $feed);
		}
	}

	private function __saveEvent($event, $user) {
		$this->Event = ClassRegistry::init('Event');
		$existingEvent = $this->Event->find('first', array(
				'conditions' => array('Event.uuid' => $event['Event']['uuid']),
				'recursive' => -1,
				'fields' => array('Event.uuid', 'Event.id', 'Event.timestamp')
		));
		$result = array();
		if (!empty($existingEvent)) {
			$result['action'] = 'edit';
			if ($existingEvent['Event']['timestamp'] < $event['Event']['timestamp']) {
				$result['result'] = $this->Event->_edit($event, true, $user);
			} else $result['result'] = 'No change';
		} else {
			$result['action'] = 'add';
			$result['result'] = $this->Event->_add($event, true, $user);
		}
		return $result;
	}

	private function __prepareEvent($body, $feed) {
		$filterRules = $this->__prepareFilterRules($feed);
		$event = json_decode($body, true);
		if (isset($event['response'])) $event = $event['response'];
		if (isset($event[0])) $event = $event[0];
		if (!isset($event['Event']['uuid'])) return false;
		$event['Event']['distribution'] = $feed['Feed']['distribution'];
		$event['Event']['sharing_group_id'] = $feed['Feed']['sharing_group_id'];
		foreach ($event['Event']['Attribute'] as &$attribute) $attribute['distribution'] = 5;
		if ($feed['Feed']['tag_id']) {
			if (!isset($event['Event']['Tag'])) $event['Event']['Tag'] = array();
			$found = false;
			if (!empty($event['Event']['Tag'])) {
				foreach ($event['Event']['Tag'] as $tag) {
					if (strtolower($tag['name']) === strtolower($feed['Tag']['name'])) $found = true;
				}
			}
			if (!$found) {
				$feedTag = $this->Tag->find('first', array('conditions' => array('Tag.id' => $feed['Feed']['tag_id']), 'recursive' => -1, 'fields' => array('Tag.name', 'Tag.colour', 'Tag.exportable')));
				if (!empty($feedTag)) $event['Event']['Tag'][] = $feedTag['Tag'];
			}
		}
		if ($feed['Feed']['sharing_group_id']) {
			$sg = $this->SharingGroup->find('first', array(
					'recursive' => -1,
					'conditions' => array('SharingGroup.id' => $feed['Feed']['sharing_group_id'])
			));
			if (!empty($sg)) {
				$event['Event']['SharingGroup'] = $sg['SharingGroup'];
			} else {
				// We have an SG ID for the feed, but the SG is gone. Make the event private as a fall-back.
				$event['Event']['distribution'] = 0;
				$event['Event']['sharing_group_id'] = 0;
			}
		}
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
			$event = $this->__prepareEvent($response->body, $feed);
			if (is_array($event)) {
				$this->Event = ClassRegistry::init('Event');
				return $this->Event->_add($event, true, $user);
			} else return $event;
		}
	}

	private function __updateEventFromFeed($HttpSocket, $feed, $uuid, $eventId, $user, $filterRules) {
		$request = $this->__createFeedRequest();
		$uri = $feed['Feed']['url'] . '/' . $uuid . '.json';
		$response = $HttpSocket->get($uri, '', $request);
		if ($response->code != 200) {
			return false;
		} else {
			$event = $this->__prepareEvent($response->body, $feed);
			$this->Event = ClassRegistry::init('Event');
			return $this->Event->_edit($event, $user, $uuid, $jobId = null);
		}
	}

	public function addDefaultFeeds($newFeeds) {
		foreach ($newFeeds as $newFeed) {
			$existingFeed = $this->find('list', array('conditions' => array('Feed.url' => $newFeed['url'])));
			$success = true;
			if (empty($existingFeed)) {
				$this->create();
				$feed = array(
						'name' => $newFeed['name'],
						'provider' => $newFeed['provider'],
						'url' => $newFeed['url'],
						'enabled' => $newFeed['enabled'],
						'distribution' => 3,
						'sharing_group_id' => 0,
						'tag_id' => 0,
						'default' => true,
				);
				$result = $this->save($feed) && $success;
			}
		}
		return $success;
	}

	public function downloadFromFeedInitiator($feedId, $user, $jobId = false) {
		$this->id = $feedId;
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$job = ClassRegistry::init('Job');
		$this->read();
		if ($jobId) {
			$job->id = $jobId;
			$job->saveField('message', 'Fetching event manifest.');
		}
		$HttpSocket = $syncTool->setupHttpSocketFeed($this->data);
		$actions = $this->getNewEventUuids($this->data, $HttpSocket);
		if ($jobId) {
			$job->id = $jobId;
			$job->saveField('message', 'Fetching events.');
		}
		$result = $this->downloadFromFeed($actions, $this->data, $HttpSocket, $user, $jobId);
		if ($jobId) {
			$job->id = $jobId;
			$job->saveField('message', 'Job complete.');
		}
		return $result;
	}
}
