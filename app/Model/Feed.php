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
			'rule' => array('urlOrExistingFilepath'),
			'message' => 'Please enter a valid url or file path (make sure that the choice matches the input source setting).',
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

	public function urlOrExistingFilepath($fields) {
		$input_source = empty($this->data['Feed']['input_source']) ? 'network' : $this->data['Feed']['input_source'];
		if ($input_source == 'local') {
			if ($this->data['Feed']['source_format'] == 'misp') {
				if (!is_dir($this->data['Feed']['url'])) {
					return 'For MISP type local feeds, please specify the containing directory.';
				}
			} else {
				if (!file_exists($this->data['Feed']['url'])) {
					return 'For non-MISP type local feeds, please specify the file to be ingested.';
				}
			}
		} else {
			if (!filter_var($this->data['Feed']['url'], FILTER_VALIDATE_URL)) {
				return false;
			}
		}
		return true;
	}

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
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (file_exists($feed['Feed']['url'] . '/manifest.json')) {
				$data = file_get_contents($feed['Feed']['url'] . '/manifest.json');
			}
		} else {
			$request = $this->__createFeedRequest();
			$uri = $feed['Feed']['url'] . '/manifest.json';
			$response = $HttpSocket->get($uri, '', $request);
			if ($response->code != 200) return 1;
			$data = $response->body;
			unset($response);
		}
		$manifest = json_decode($data, true);
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
			if ($event['Event']['timestamp'] < $manifest[$event['Event']['uuid']]['timestamp']) {
				$result['edit'][] = array('uuid' => $event['Event']['uuid'], 'id' => $event['Event']['id']);
			} else {
				$this->__cleanupFile($feed, '/' . $event['Event']['uuid'] . '.json');
			}
			unset($manifest[$event['Event']['uuid']]);
		}
		if (!empty($manifest)) {
			$result['add'] = array_keys($manifest);
		}
		return $result;
	}

	public function getCache($feed, $HttpSocket) {
		$result = array();
		$request = $this->__createFeedRequest();
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (file_exists($feed['Feed']['url'] . '/hashes.csv')) {
				$data = file_get_contents($feed['Feed']['url'] . '/hashes.csv');
				if (empty($data)) return false;
			} else {
				return false;
			}
		} else {
			$uri = $feed['Feed']['url'] . '/hashes.csv';
			try {
				$response = $HttpSocket->get($uri, '', $request);
			} catch (Exception $e) {
				return false;
			}
			if ($response->code != 200) {
				return false;
			}
			$data = $response->body;
			unset($response);
		}
		try {
			$data = trim($data);
			$data = explode("\n", $data);
			foreach ($data as $k => $v) {
				$data[$k] = explode(',', $v);
			}
		} catch (Exception $e) {
			return false;
		}
		return $data;
	}


	public function getManifest($feed, $HttpSocket) {
		$result = array();
		$request = $this->__createFeedRequest();
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (file_exists($feed['Feed']['url'] . '/manifest.json')) {
				$data = file_get_contents($feed['Feed']['url'] . '/manifest.json');
				if (empty($data)) return false;
			} else {
				throw new NotFoundException('Invalid file.');
			}
		} else {
			$uri = $feed['Feed']['url'] . '/manifest.json';
			try {
				$response = $HttpSocket->get($uri, '', $request);
			} catch (Exception $e) {
				return $e->getMessage();
			}
			if ($response->code != 200) {
				return 'Fetching the manifest failed with error: ' . $response->code;
			}
			$data = $response->body;
			unset($response);
		}
		try {
			$events = json_decode($data, true);
		} catch (Exception $e) {
			return 'Invalid MISP JSON returned.';
		}
		$events = $this->__filterEventsIndex($events, $feed);
		return $events;
	}

	private function __getRecursive($url, $query, $request, $iterations = 0) {
		if ($iterations == 5) return false;
		$HttpSocket = $this->__setupHttpSocket(false);
		$response = $HttpSocket->get($url, $query, $request);
		if ($response->code == 302 || $response->code == 301) {
			$response = $this->__getRecursive($response['header']['Location'], $query, $request, $iterations + 1);
		}
		return $response;
	}

	public function getFreetextFeed($feed, $HttpSocket, $type = 'freetext', $page = 1, $limit = 60, &$params = array()) {
		$result = array();
		$data = '';
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (file_exists($feed['Feed']['url'])) {
				$data = file_get_contents($feed['Feed']['url']);
			}
		} else {
			$feedCache = APP . 'tmp' . DS . 'cache' . DS . 'misp_feed_' . intval($feed['Feed']['id']) . '.cache';
			$doFetch = true;
			if (file_exists($feedCache)) {
				$file = new File($feedCache);
				if (time() - $file->lastChange() < 600) {
					$doFetch = false;
					$data = file_get_contents($feedCache);
				}
			}
			if ($doFetch) {
				$fetchIssue = false;
				try {
					$response = $this->__getRecursive($feed['Feed']['url'], '', array());
					//$response = $HttpSocket->get($feed['Feed']['url'], '', array());
				} catch (Exception $e) {
					return $e->getMessage();
				}
				if ($response->code == 200) {
					$redis = $this->setupRedis();
					if ($redis === false) {
							return 'Could not reach Redis.';
					}
						$redis->del('misp:feed_cache:' . $feed['Feed']['id']);
					$data = $response->body;
					file_put_contents($feedCache, $data);
				} else {
					return 'Invalid response code returned: ' . $response->code;
				}
			}
		}
		App::uses('ComplexTypeTool', 'Tools');
		$complexTypeTool = new ComplexTypeTool();
		$this->Warninglist = ClassRegistry::init('Warninglist');
		$complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
		$settings = array();
		if (!empty($feed['Feed']['settings']) && !is_array($feed['Feed']['settings'])) {
			$feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
		}
		if (isset($feed['Feed']['settings'][$type])) {
			$settings = $feed['Feed']['settings'][$type];
		}
		if (isset($feed['Feed']['settings']['common'])) {
			$settings = array_merge($settings, $feed['Feed']['settings']['common']);
		}
		$resultArray = $complexTypeTool->checkComplexRouter($data, $type, $settings);
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

	public function getFreetextFeedCorrelations($data, $feedId) {
		$values = array();
		foreach ($data as $key => $value) {
			$values[] = $value['value'];
		}
		$this->Attribute = ClassRegistry::init('Attribute');
		$redis = $this->setupRedis();
		if ($redis !== false) {
			$feeds = $this->find('all', array(
				'recursive' => -1,
				'conditions' => array('Feed.id !=' => $feedId),
				'fields' => array('id', 'name', 'url', 'provider', 'source_format')
			));
			foreach ($feeds as $k => $v) {
				if (!$redis->exists('misp:feed_cache:' . $v['Feed']['id'])) {
					unset($feeds[$k]);
				}
			}
		} else {
			return array();
		}
		// Adding a 3rd parameter to a list find seems to allow grouping several results into a key. If we ran a normal list with value => event_id we'd only get exactly one entry for each value
		// The cost of this method is orders of magnitude lower than getting all id - event_id - value triplets and then doing a double loop comparison
		$correlations = $this->Attribute->find('list', array('conditions' => array('Attribute.value1' => $values, 'Attribute.deleted' => 0), 'fields' => array('Attribute.event_id', 'Attribute.event_id', 'Attribute.value1')));
		$correlations2 = $this->Attribute->find('list', array('conditions' => array('Attribute.value2' => $values, 'Attribute.deleted' => 0), 'fields' => array('Attribute.event_id', 'Attribute.event_id', 'Attribute.value2')));
		$correlations = array_merge_recursive($correlations, $correlations2);
		foreach ($data as $key => $value) {
			if (isset($correlations[$value['value']])) {
				$data[$key]['correlations'] = array_values($correlations[$value['value']]);
			}
			if ($redis) {
				foreach ($feeds as $k => $v) {
					if ($redis->sismember('misp:feed_cache:' . $v['Feed']['id'], md5($value['value']))) {
						$data[$key]['feed_correlations'][] = array($v);
					} else {
					}
				}
			}
		}
		return $data;
	}

	public function attachFeedCorrelations($objects, $user, &$event, $overrideLimit = false) {
		$redis = $this->setupRedis();
		if ($redis !== false) {
			$params = array(
				'recursive' => -1,
				'fields' => array('id', 'name', 'url', 'provider', 'source_format')
			);
			if (!$user['Role']['perm_site_admin']) {
				$params['conditions'] = array('Feed.lookup_visible' => 1);
			}
			$feeds = $this->find('all', $params);
			$counter = 0;
			$hashTable = array();
			$feedList = array();
			$pipe = $redis->multi(Redis::PIPELINE);
			$objectsWithFeedHits = array();
			$hashTable = array();
			$hitIds = array();
			$this->Event = ClassRegistry::init('Event');
			foreach ($objects as $k => $object) {
				if (in_array($object['type'], $this->Event->Attribute->getCompositeTypes())) {
					$value = explode('|', $object['value']);
					$hashTable[$k] = md5($value[0]);
				} else {
					$hashTable[$k] = md5($object['value']);
				}
				$redis->sismember('misp:feed_cache:combined', $hashTable[$k]);
			}
			$results = $pipe->exec();
			if (!$overrideLimit && count($objects) > 10000) {
				foreach ($results as $k => $result) {
					if ($result) {
						if (isset($event['FeedCount'])) $event['FeedCount']++;
						else $event['FeedCount'] = 1;
						$objects[$k]['FeedHit'] = true;
					}
				}
			} else {
				foreach ($results as $k => $result) {
					if ($result) {
							$hitIds[] = $k;
					}
				}
				foreach ($feeds as $k3 => $feed) {
					$pipe = $redis->multi(Redis::PIPELINE);
					foreach ($hitIds as $k2 => $k) {
						$redis->sismember('misp:feed_cache:' . $feed['Feed']['id'], $hashTable[$k]);
					}
					$feedHits = $pipe->exec();
					foreach ($feedHits as $k4 => $hit) {
						if ($hit) {
							if (!isset($event['Feed'][$feeds[$k3]['Feed']['id']])) {
								$event['Feed'][$feeds[$k3]['Feed']['id']] = $feed['Feed'];
							}
							$objects[$hitIds[$k4]]['Feed'][] = $feed['Feed'];
						}
					}
					if ($feed['Feed']['source_format'] == 'misp') {
						$pipe = $redis->multi(Redis::PIPELINE);
						$eventUuidHitPosition = array();
						$i = 0;
						foreach ($objects as $k => $object) {
							if (isset($object['Feed'])) {
								foreach ($object['Feed'] as $currentFeed) {
									if ($feed['Feed']['id'] == $currentFeed['id']) {
										$eventUuidHitPosition[$i] = $k;
										$i++;
										if (in_array($object['type'], $this->Event->Attribute->getCompositeTypes())) {
											$value = explode('|', $object['value']);
											$redis->smembers('misp:feed_cache:event_uuid_lookup:' . md5($value[0]));
										} else {
											$redis->smembers('misp:feed_cache:event_uuid_lookup:' . md5($object['value']));
										}
									}
								}
							}
						}
						$mispFeedHits = $pipe->exec();
						foreach ($mispFeedHits as $feedhitPos => $f) {
							foreach ($f as $url) {
								$urlParts = explode('/', $url);
								if (empty($event['Feed'][$urlParts[0]]['event_uuids']) || !in_array($urlParts[1], $event['Feed'][$urlParts[0]]['event_uuids'])) {
									$event['Feed'][$urlParts[0]]['event_uuids'][] = $urlParts[1];
								}
								foreach ($objects[$eventUuidHitPosition[$feedhitPos]]['Feed'] as $tempKey => $tempFeed) {
									if ($tempFeed['id'] == $urlParts[0]) {
										$objects[$eventUuidHitPosition[$feedhitPos]]['Feed'][$tempKey]['event_uuids'][] = $urlParts[1];
									}
								}
							}
						}
					}
				}
			}
		}
		if (!empty($event['Feed'])) $event['Feed'] = array_values($event['Feed']);
		return $objects;
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
				$this->__cleanupFile($feed, '/' . $uuid . '.json');
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
				if ($result === 'blocked') continue;
				$result = $this->__updateEventFromFeed($HttpSocket, $feed, $editTarget['uuid'], $editTarget['id'], $user, $filterRules);
				$this->__cleanupFile($feed, '/' . $uuid . '.json');
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
					'MISP-uuid' => Configure::read('MISP.uuid')
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
		$path = $feed['Feed']['url'] . '/' . $uuid . '.json';
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (file_exists($path)) {
				$data = file_get_contents($path);
			}
		} else {
			$HttpSocket = $this->__setupHttpSocket($feed);
			$request = $this->__createFeedRequest();
			$response = $HttpSocket->get($path, '', $request);
			if ($response->code != 200) {
				return false;
			}
			$data = $response->body;
			unset($response->body);
		}
		return $this->__prepareEvent($data, $feed);
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
		if (!empty($event['Event']['Attribute'])) {
			foreach ($event['Event']['Attribute'] as $key => $attribute) $event['Event']['Attribute'][$key]['distribution'] = 5;
		}
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
		if (!Validation::uuid($uuid)) {
			return false;
		}
		$path = $feed['Feed']['url'] . '/' . $uuid . '.json';
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (file_exists($path)) {
				$data = file_get_contents($path);
			}
		} else {
			$request = $this->__createFeedRequest();
			$response = $HttpSocket->get($path, '', $request);
			if ($response->code != 200) {
				return false;
			}
			$data = $response->body;
			unset($response);
		}
		$event = $this->__prepareEvent($data, $feed);
		if (is_array($event)) {
			$this->Event = ClassRegistry::init('Event');
			return $this->Event->_add($event, true, $user);
		} else return $event;
	}

	private function __updateEventFromFeed($HttpSocket, $feed, $uuid, $eventId, $user, $filterRules) {
		if (!Validation::uuid($uuid)) {
			return false;
		}
		$path = $feed['Feed']['url'] . '/' . $uuid . '.json';
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (file_exists($path)) {
				$data = file_get_contents($path);
			}
		} else {
			$request = $this->__createFeedRequest();
			$response = $HttpSocket->get($path, '', $request);
			if ($response->code != 200) {
				return false;
			}
		}
		$event = $this->__prepareEvent($response->body, $feed);
		$this->Event = ClassRegistry::init('Event');
		return $this->Event->_edit($event, $user, $uuid, $jobId = null);
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
		if (isset($this->data['Feed']['input_source']) && $this->data['Feed']['input_source'] == 'local') {
			$HttpSocket = false;
		} else {
			$HttpSocket = $syncTool->setupHttpSocketFeed($this->data);
		}
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
			if (empty($actions)) {
				if ($jobId) {
					$job->id = $jobId;
					$job->saveField('message', 'Job complete.');
				}
				return true;
			}
			$result = $this->downloadFromFeed($actions, $this->data, $HttpSocket, $user, $jobId);
			$this->__cleanupFile($this->data, '/manifest.json');
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
			$data = array();
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
			$this->__cleanupFile($this->data, '');
			if ($jobId) {
				$job->saveField('progress', '100');
				$job->saveField('message', 'Job complete.');
			}
		}
		return $result;
	}

	private function __cleanupFile($feed, $file) {
		if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
			if (isset($feed['Feed']['delete_local_file']) && $feed['Feed']['delete_local_file']) {
				if (file_exists($feed['Feed']['url'] . $file)) {
					unlink($feed['Feed']['url'] . $file);
				}
			}
		}
		return true;
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
			$temp = $this->Event->Attribute->find('all', array(
				'conditions' => array(
					'Attribute.deleted' => 0,
					'Attribute.event_id' => $event['Event']['id']
				),
				'recursive' => -1,
				'fields' => array('id', 'value1', 'value2')
			));
			$event['Attribute'] = array();
			foreach ($temp as $k => $t) {
				if (!empty($t['Attribute']['value2'])) {
					$t['Attribute']['value'] = $t['Attribute']['value1'] . '|' . $t['Attribute']['value2'];
				} else {
					$t['Attribute']['value'] = $t['Attribute']['value1'];
				}
				$event['Attribute'][$t['Attribute']['id']] = $t['Attribute']['value'];
			}
			unset($temp);
			$to_delete = array();
			foreach ($data as $k => $dataPoint) {
				$finder = array_search($dataPoint['value'], $event['Attribute']);
				if ($finder !== false) {
					unset($data[$k]);
					unset($event['Attribute'][$finder]);
				}
			}
			if ($feed['Feed']['delta_merge']) {
				foreach ($event['Attribute'] as $k => $attribute) {
					$to_delete[] = $k;
				}
				if (!empty($to_delete)) {
					$this->Event->Attribute->deleteAll(array('Attribute.id' => $to_delete, 'Attribute.deleted' => 0));
				}
			}
		}
		$data = array_values($data);
		if (empty($data)) {
			return true;
		}
		$uniqueValues = array();
		foreach ($data as $key => $value) {
			if (in_array($value['value'], $uniqueValues)) {
				unset($data[$key]);
				continue;
			}
			$data[$key]['event_id'] = $event['Event']['id'];
			$data[$key]['distribution'] = $feed['Feed']['distribution'];
			$data[$key]['sharing_group_id'] = $feed['Feed']['sharing_group_id'];
			$data[$key]['to_ids'] = $feed['Feed']['override_ids'] ? 0 : $data[$key]['to_ids'];
			$uniqueValues[] = $data[$key]['value'];
		}
		$data = array_values($data);
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->id = $jobId;
		}
		foreach ($data as $k => $chunk) {
			$this->Event->Attribute->create();
			$this->Event->Attribute->save($chunk);
			if ($jobId && $k % 100 == 0) {
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

	public function cacheFeedInitiator($user, $jobId = false, $scope = 'freetext') {
		$params = array(
			'conditions' => array('enabled' => 1),
			'recursive' => -1,
			'fields' => array('source_format', 'input_source', 'url', 'id', 'settings')
		);
		$redis = $this->setupRedis();
		if ($redis === false) {
			return 'Redis not reachable.';
		}
		if ($scope !== 'all') {
			if (is_numeric($scope)) {
				$params['conditions']['id'] = $scope;
			} else if ($scope == 'freetext' || $scope == 'csv') {
				$params['conditions']['source_format'] = array('csv', 'freetext');
			} else if ($scope == 'misp') {
				$redis->del('misp:feed_cache:event_uuid_lookup:');
				$params['conditions']['source_format'] = 'misp';
			}
		} else {
			$redis->del('misp:feed_cache:combined');
			$redis->del('misp:feed_cache:event_uuid_lookup:');
		}
		$feeds = $this->find('all', $params);
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->id = $jobId;
			if (!$job->exists()) {
				$jobId = false;
			}
		}
		foreach ($feeds as $k => $feed) {
			$this->__cacheFeed($feed, $redis, $jobId);
			if ($jobId) {
				$job->saveField('progress', 100 * $k / count($feeds));
				$job->saveField('message', 'Feed ' . $feed['Feed']['id'] . ' cached.');
			}
		}
		return true;
	}

	public function attachFeedCacheTimestamps($data) {
		$redis = $this->setupRedis();
		if ($redis === false) {
			return $data;
		}
		foreach ($data as $k => $v) {
			$data[$k]['Feed']['cache_timestamp'] = $redis->get('misp:feed_cache_timestamp:' . $data[$k]['Feed']['id']);
		}
		return $data;
	}

	private function __cacheFeed($feed, $redis, $jobId = false) {
		if ($feed['Feed']['input_source'] == 'local') {
			$HttpSocket = false;
		} else {
			$HttpSocket = $this->__setupHttpSocket($feed);
		}
		if ($feed['Feed']['source_format'] == 'misp') {
			return $this->__cacheMISPFeed($feed, $redis, $HttpSocket, $jobId);
		} else {
			return $this->__cacheFreetextFeed($feed, $redis, $HttpSocket, $jobId);
		}
	}

	private function __cacheFreetextFeed($feed, $redis, $HttpSocket, $jobId = false) {
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->id = $jobId;
			if (!$job->exists()) {
				$jobId = false;
			}
		}
		$values = $this->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format'], 'all');
		if (!empty($values)) {
			foreach ($values as $k => $value) {
				$redis->sAdd('misp:feed_cache:' . $feed['Feed']['id'], md5($value['value']));
				$redis->sAdd('misp:feed_cache:combined', md5($value['value']));
				if ($jobId && ($k % 1000 == 0)) {
						$job->saveField('message', 'Feed ' . $feed['Feed']['id'] . ': ' . $k . ' values cached.');
				}
			}
			$redis->set('misp:feed_cache_timestamp:' . $feed['Feed']['id'], time());
			return true;
		}
		return false;
	}

	private function __cacheMISPFeedTraditional($feed, $redis, $HttpSocket, $jobId = false) {
		$this->Attribute = ClassRegistry::init('Attribute');
		$manifest = $this->getManifest($feed, $HttpSocket);
		if (!empty($manifest)) {
			$redis->del('misp:feed_cache:' . $feed['Feed']['id']);
		} else {
			return false;
		}
		$k = 0;
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->id = $jobId;
		}
		foreach ($manifest as $uuid => $event) {
			$data = false;
			$path = $feed['Feed']['url'] . '/' . $uuid . '.json';
			if (isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] == 'local') {
				if (file_exists($path)) {
					$data = file_get_contents($path);
				}
			} else {
				$HttpSocket = $this->__setupHttpSocket($feed);
				$request = $this->__createFeedRequest();
				$fetchIssue = false;
				try {
					$response = $HttpSocket->get($path, '', $request);
				} catch (Exception $e) {
					$fetchIssue = true;
				}
				if ($fetchIssue || $response->code != 200) {
					return false;
				}
				$data = $response->body;
			}
			if ($data) {
				$event = json_decode($data, true);
				if (!empty($event['Event']['Attribute'])) {
					$pipe = $redis->multi(Redis::PIPELINE);
					foreach ($event['Event']['Attribute'] as $attribute) {
						if (!in_array($attribute['type'], $this->Attribute->nonCorrelatingTypes)) {
							if (in_array($attribute['type'], $this->Attribute->getCompositeTypes())) {
								$value = explode('|', $attribute['value']);
								$redis->sAdd('misp:feed_cache:' . $feed['Feed']['id'], md5($value[0]));
								$redis->sAdd('misp:feed_cache:' . $feed['Feed']['id'], md5($value[1]));
								$redis->sAdd('misp:feed_cache:combined', md5($value[0]));
								$redis->sAdd('misp:feed_cache:combined', md5($value[1]));
								$redis->sAdd('misp:feed_cache:event_uuid_lookup:' . md5($value[0]), $feed['Feed']['id'] . '/' . $event['Event']['uuid']);
								$redis->sAdd('misp:feed_cache:event_uuid_lookup:' . md5($value[1]), $feed['Feed']['id'] . '/' . $event['Event']['uuid']);
							} else {
								$redis->sAdd('misp:feed_cache:' . $feed['Feed']['id'], md5($attribute['value']));
								$redis->sAdd('misp:feed_cache:combined', md5($attribute['value']));
								$redis->sAdd('misp:feed_cache:event_uuid_lookup:' . md5($attribute['value']), $feed['Feed']['id'] . '/' . $event['Event']['uuid']);
							}
						}
					}
					$pipe->exec();
				}
			}
			$k++;
			if ($jobId && ($k % 10 == 0)) {
					$job->saveField('message', 'Feed ' . $feed['Feed']['id'] . ': ' . $k . ' events cached.');
			}
		}
		return true;
	}

	private function __cacheMISPFeedCache($feed, $redis, $HttpSocket, $jobId = false) {
		$cache = $this->getCache($feed, $HttpSocket);
		if (empty($cache)) return false;
		$pipe = $redis->multi(Redis::PIPELINE);
		$events = array();
		foreach ($cache as $k => $v) {
			$redis->sAdd('misp:feed_cache:' . $feed['Feed']['id'], $v[0]);
			$redis->sAdd('misp:feed_cache:combined', $v[0]);
			$redis->sAdd('misp:feed_cache:event_uuid_lookup:' . $v[0], $feed['Feed']['id'] . '/' . $v[1]);
		}
		$pipe->exec();
		if ($jobId) {
				$job = ClassRegistry::init('Job');
				$job->id = $jobId;
				$job->saveField('message', 'Feed ' . $feed['Feed']['id'] . ': cached via quick cache.');
		}
		return true;
	}

	private function __cacheMISPFeed($feed, $redis, $HttpSocket, $jobId = false) {
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->id = $jobId;
			if (!$job->exists()) {
				$jobId = false;
			}
		}
		if (!$this->__cacheMISPFeedCache($feed, $redis, $HttpSocket, $jobId)) {
			$this->__cacheMISPFeedTraditional($feed, $redis, $HttpSocket, $jobId);
		};
		$redis->set('misp:feed_cache_timestamp:' . $feed['Feed']['id'], time());
		return true;
	}

	public function compareFeeds($id = false) {
		$redis = $this->setupRedis();
		if ($redis === false) {
			return array();
		}
		$fields = array('id', 'input_source', 'source_format', 'url', 'provider', 'name', 'default');
		$feeds = $this->find('all', array(
			'recursive' => -1,
			'fields' => $fields
		));
		// we'll use this later for the intersect
		$fields[] = 'values';
		$fields = array_flip($fields);
		// Get all of the feed cache cardinalities for all feeds - if a feed is not cached remove it from the list
		foreach ($feeds as $k => $feed) {
			if (!$redis->exists('misp:feed_cache:' . $feed['Feed']['id'])) {
				unset($feeds[$k]);
				continue;
			}
			$feeds[$k]['Feed']['values'] = $redis->sCard('misp:feed_cache:' . $feed['Feed']['id']);
		}
		$feeds = array_values($feeds);
		foreach ($feeds as $k => $feed) {
			foreach ($feeds as $k2 => $feed2) {
				if ($k == $k2) continue;
				$intersect = $redis->sInter('misp:feed_cache:' . $feed['Feed']['id'], 'misp:feed_cache:' . $feed2['Feed']['id']);
				$feeds[$k]['Feed']['ComparedFeed'][] = array_merge(array_intersect_key($feed2['Feed'], $fields), array(
					'overlap_count' => count($intersect),
					'overlap_percentage' => round(100 * count($intersect) / $feeds[$k]['Feed']['values']),
				));
			}
		}
		return $feeds;
	}

	public function importFeeds($feeds, $user, $default = false) {
		$feeds = json_decode($feeds, true);
		if (!isset($feeds[0])) {
			$feeds = array($feeds);
		}
		$results = array('successes' => 0, 'fails' => 0);
		if (empty($feeds)) return $results;
		$existingFeeds = $this->find('all', array());
		foreach ($feeds as $feed) {
			if ($default) {
				$feed['Feed']['default'] = 1;
			} else {
				$feed['Feed']['default'] = 0;
			}
			if (isset($feed['Feed']['id'])) {
				unset($feed['Feed']['id']);
			}
			$found = false;
			foreach ($existingFeeds as $existingFeed) {
				if ($existingFeed['Feed']['url'] == $feed['Feed']['url']) {
					$found = true;
				}
			}
			if (!$found) {
				$feed['Feed']['tag_id'] = 0;
				if (isset($feed['Tag'])) {
					$tag_id = $this->Tag->captureTag($feed['Tag'], $user);
					if ($tag_id) $feed['Feed']['tag_id'] = $tag_id;
				}
				$this->create();
				if (!$this->save($feed, true, array('name', 'provider', 'url', 'rules', 'source_format', 'fixed_event', 'delta_merge', 'override_ids', 'publish', 'settings', 'tag_id', 'default', 'lookup_visible'))) {
					$results['fails']++;
				} else {
					$results['successes']++;
				}
			}
		}
		return $results;
	}

	public function load_default_feeds() {
		$user = array('Role' => array('perm_tag_editor' => 1, 'perm_site_admin' => 1));
		$json = file_get_contents(APP . 'files/feed-metadata/defaults.json');
		$this->importFeeds($json, $user, true);
		return true;
	}
}
