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

	public $validate = array(
		'url' => array( // TODO add extra validation to refuse multiple time the same url from the same org
			'rule' => array('url'),
			'message' => 'Please enter a valid url.',
		),
		'provider' => 'valueNotEmpty',
		'name' => 'valueNotEmpty',
		'event_id' => array(
			'rule' => array('numeric'),
			'message' => 'Please enter a numeric event ID or leave this field blank.',
		)
	);

	// currently we only have an internal name and a display name, but later on we can expand this with versions, default settings, etc
	public $feed_types = array(
		'misp' => array(
			'name' => 'MISP Feed'
		),
		'freetext' => array(
			'name' => 'Freetext Parsed Feed'
		),
		'csv' => array(
				'name' => 'Simple CSV Parsed Feed'
		)
	);

	public function getFeedTypesOptions() {
		$result = array();
		foreach ($this->feed_types as $key => $value) {
			$result[$key] = $value['name'];
		}
		return $result;
	}

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
		foreach ($events as $event) {
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

	public function getFreetextFeed($feed, $HttpSocket, $type = 'freetext', $page = 1, $limit = 60, &$params = array()) {
		$result = array();
		$feedCache = APP . 'tmp' . DS . 'cache' . DS . 'feeds' . DS . intval($feed['Feed']['id']) . '.cache';
		$doFetch = true;
		if (file_exists($feedCache)) {
			$file = new File($feedCache);
			if (time() - $file->lastChange() < 600) {
				$doFetch = false;
				$data = file_get_contents($feedCache);
			}
		}
		if ($doFetch) {
			$response = $HttpSocket->get($feed['Feed']['url'], '', array());
			if ($response->code == 200) {
				$data = $response->body;
				file_put_contents($feedCache, $data);
			}
		}
		App::uses('ComplexTypeTool', 'Tools');
		$complexTypeTool = new ComplexTypeTool();
		$this->Warninglist = ClassRegistry::init('Warninglist');
		$complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
		$resultArray = $complexTypeTool->checkComplexRouter($data, $type, isset($feed['Feed']['settings'][$type]) ? $feed['Feed']['settings'][$type] : array());
		$this->Attribute = ClassRegistry::init('Attribute');
		foreach ($resultArray as $key => $value) {
			$resultArray[$key]['category'] = $this->Attribute->typeDefinitions[$value['default_type']]['default_category'];
		}
		App::uses('CustomPaginationTool', 'Tools');
		$customPagination = new CustomPaginationTool();
		$params = $customPagination->createPaginationRules($resultArray, array('page' => $page, 'limit' => $limit), 'Feed', $sort = false);
		if (!empty($page) && $page != 'all') {
			$start = ($page - 1) * $limit;
			if ($start > count($resultArray)) {
				return false;
			}
			$resultArray = array_slice($resultArray, $start, $limit);
		}

		return $resultArray;
	}

	public function getFreetextFeedCorrelations($data) {
		$values = array();
		foreach ($data as $key => $value) {
			$values[] = $value['value'];
		}
		$this->Attribute = ClassRegistry::init('Attribute');
		// Adding a 3rd parameter to a list find seems to allow grouping several results into a key. If we ran a normal list with value => event_id we'd only get exactly one entry for each value
		// The cost of this method is orders of magnitude lower than getting all id - event_id - value triplets and then doing a double loop comparison
		$correlations = $this->Attribute->find('list', array('conditions' => array('Attribute.value1' => $values, 'Attribute.deleted' => 0), 'fields' => array('Attribute.event_id', 'Attribute.event_id', 'Attribute.value1')));
		$correlations2 = $this->Attribute->find('list', array('conditions' => array('Attribute.value2' => $values, 'Attribute.deleted' => 0), 'fields' => array('Attribute.event_id', 'Attribute.event_id', 'Attribute.value2')));
		$correlations = array_merge_recursive($correlations, $correlations2);
		foreach ($data as $key => $value) {
			if (isset($correlations[$value['value']])) {
				$data[$key]['correlations'] = array_values($correlations[$value['value']]);
			}
		}
		return $data;
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
		try {
			$commit = trim(shell_exec('git log --pretty="%H" -n1 HEAD'));
		} catch (Exception $e) {
			$commit = false;
		}

		$result = array(
			'header' => array(
					'Accept' => 'application/json',
					'Content-Type' => 'application/json',
					'MISP-version' => $version,
			)
		);
		if ($commit) {
			$result['header']['commit'] = $commit;
		}
		return $result;
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
		foreach ($events as $k => $event) {
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
				foreach ($event['Tag'] as $tag) {
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
					foreach ($event['Tag'] as $tag) {
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
		foreach ($event['Event']['Attribute'] as $key => $attribute) $event['Event']['Attribute'][$key]['distribution'] = 5;
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
		if (isset($this->data['Feed']['settings']) && !empty($this->data['Feed']['settings'])) {
			$this->data['Feed']['settings'] = json_decode($this->data['Feed']['settings'], true);
		}
		$HttpSocket = $syncTool->setupHttpSocketFeed($this->data);
		if ($this->data['Feed']['source_format'] == 'misp') {
			if ($jobId) {
				$job->id = $jobId;
				$job->saveField('message', 'Fetching event manifest.');
			}
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
		} else {
			if ($jobId) {
				$job->id = $jobId;
				$job->saveField('message', 'Fetching data.');
			}
			$temp = $this->getFreetextFeed($this->data, $HttpSocket, $this->data['Feed']['source_format'], 'all');
			foreach ($temp as $key => $value) {
				$data[] = array(
					'category' => $value['category'],
					'type' => $value['default_type'],
					'value' => $value['value'],
					'to_ids' => $value['to_ids']
				);
			}
			if ($jobId) {
				$job->saveField('progress', 50);
				$job->saveField('message', 'Saving data.');
			}
			$result = $this->saveFreetextFeedData($this->data, $data, $user);
			$message = 'Job complete.';
			if ($result !== true) {
				return false;
			}
			if ($jobId) {
				$job->saveField('progress', '100');
				$job->saveField('message', 'Job complete.');
			}
		}
		return $result;
	}

	public function saveFreetextFeedData($feed, $data, $user, $jobId = false) {
		$this->Event = ClassRegistry::init('Event');
		$event = false;
		if ($feed['Feed']['fixed_event'] && $feed['Feed']['event_id']) {
			$event = $this->Event->find('first', array('conditions' => array('Event.id' => $feed['Feed']['event_id']), 'recursive' => -1));
			if (empty($event)) return 'The target event is no longer valid. Make sure that the target event exists.';
		}
		if (!$event) {
			$this->Event->create();
			$event = array(
					'info' => $feed['Feed']['name'] . ' feed',
					'analysis' => 2,
					'threat_level_id' => 4,
					'orgc_id' => $user['org_id'],
					'org_id' => $user['org_id'],
					'date' => date('Y-m-d'),
					'distribution' => $feed['Feed']['distribution'],
					'sharing_group_id' => $feed['Feed']['sharing_group_id'],
					'user_id' => $user['id']
			);
			$result = $this->Event->save($event);
			if (!$result) return 'Something went wrong while creating a new event.';
			$event = $this->Event->find('first', array('conditions' => array('Event.id' => $this->Event->id), 'recursive' => -1));
			if (empty($event)) return 'The newly created event is no longer valid. Make sure that the target event exists.';
			if ($feed['Feed']['fixed_event']) {
				$feed['Feed']['event_id'] = $event['Event']['id'];
				if (!empty($feed['Feed']['settings'])) $feed['Feed']['settings'] = json_encode($feed['Feed']['settings']);
				$this->save($feed);
			}
		}
		if ($feed['Feed']['fixed_event']) {
			$event = $this->Event->find('first', array('conditions' => array('Event.id' => $event['Event']['id']), 'recursive' => -1, 'contain' => array('Attribute' => array('conditions' => array('Attribute.deleted' => 0)))));
			$to_delete = array();
			foreach ($data as $k => $dataPoint) {
				foreach ($event['Attribute'] as $attribute_key => $attribute) {
					if ($dataPoint['value'] == $attribute['value'] && $dataPoint['type'] == $attribute['type'] && $attribute['category'] == $dataPoint['category']) {
						unset($data[$k]);
						unset($event['Attribute'][$attribute_key]);
					}
				}
			}
			if ($feed['Feed']['delta_merge']) {
				foreach ($event['Attribute'] as $attribute) {
					$to_delete[] = $attribute['id'];
				}
				if (!empty($to_delete)) {
					$this->Event->Attribute->deleteAll(array('Attribute.id' => $to_delete));
				}
			}
		}
		$data = array_values($data);
		if (empty($data)) {
			return true;
		}
		foreach ($data as $key => $value) {
			$data[$key]['event_id'] = $event['Event']['id'];
			$data[$key]['distribution'] = $feed['Feed']['distribution'];
			$data[$key]['sharing_group_id'] = $feed['Feed']['sharing_group_id'];
			$data[$key]['to_ids'] = $feed['Feed']['override_ids'] ? 0 : $data[$key]['to_ids'];
		}
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->id = $jobId;
		}
		$data = array_chunk($data, 100);
		foreach ($data as $k => $chunk) {
			$this->Event->Attribute->saveMany($chunk);
			if ($jobId) {
				$job->saveField('progress', 50 + round((50 * ((($k + 1) * 100) / count($data)))));
			}
		}
		if ($feed['Feed']['publish']) {
			$this->Event->publishRouter($event['Event']['id'], null, $user);
		}
		if ($feed['Feed']['tag_id']) {
			$this->Event->EventTag->attachTagToEvent($event['Event']['id'], $feed['Feed']['tag_id']);
		}
		return true;
	}
}
