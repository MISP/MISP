<?php
App::uses('AppController', 'Controller');

class SightingsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
		if (Configure::read('Plugin.Sightings_enable') === false) throw new MethodNotAllowedException('This feature is not enabled on this instance.');
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array('Sighting.date_sighting' => 'DESC'),
	);

	// takes an attribute ID or UUID
	public function add($id = false) {
		if (!$this->userRole['perm_add']) throw new MethodNotAllowedException('You are not authorised to add sightings data as you don\'t have write access.');
		if ($this->request->is('post')) {
			$now = time();
			$values = false;
			$timestamp = false;
			$error = false;
			if ($id === 'stix') {
				$result = $this->Sighting->handleStixSighting(file_get_contents('php://input'));
				if ($result['success']) {
					$result['data'] = json_decode($result['data'], true);
					$timestamp = isset($result['data']['timestamp']) ? strtotime($result['data']['timestamp']) : $now;
					$type = '0';
					$source = '';
					if (isset($result['data']['values'])) $values = $result['data']['values'];
					else $error = 'No valid values found that could be extracted from the sightings document.';
				} else {
					$error = $result['message'];
				}
			} else {
				if (isset($this->request->data['request'])) $this->request->data = $this->request->data['request'];
				if (isset($this->request->data['Sighting'])) $this->request->data = $this->request->data['Sighting'];
				if (!empty($this->request->data['date']) && !empty($this->request->data['time'])) {
					$timestamp = DateTime::createFromFormat('Y-m-d:H:i:s', $this->request->data['date'] . ':' . $this->request->data['time']);
					$timestamp = $timestamp->getTimestamp();
				} else {
					$timestamp = isset($this->request->data['timestamp']) ? $this->request->data['timestamp'] : $now;
				}
				if (isset($this->request->data['value'])) $this->request->data['values'] = array($this->request->data['value']);
				$values = isset($this->request->data['values']) ? $this->request->data['values'] : false;
				if (!$id && isset($this->request->data['id'])) $id = $this->request->data['id'];
				$type = isset($this->request->data['type']) ? $this->request->data['type'] : '0';
				$source = isset($this->request->data['source']) ? trim($this->request->data['source']) : '';
			}
			if (!$error) {
				$result = $this->Sighting->saveSightings($id, $values, $timestamp, $this->Auth->user(), $type, $source);
			}
			if (!is_numeric($result)) {
				$error = $result;
			}
			if ($this->request->is('ajax')) {
				if ($error) {
					$error_message = 'Could not add the Sighting. Reason: ' . $error;
					return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $error_message)), 'status' => 200, 'type' => 'json'));
				} else {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $result . ' ' . $this->Sighting->type[$type] . (($result == 1) ? '' : 's') . '  added.')), 'status' => 200, 'type' => 'json'));
				}
			} else {
				if ($error) {
					return $this->RestResponse->saveFailResponse('Sighting', 'add', $id, $error);
				} else {
					return $this->RestResponse->saveSuccessResponse('Sighting', 'add', $id, false, $result . ' ' . $this->Sighting->type[$type] . (($result == 1) ? '' : 's') . ' successfuly added.');
				}
			}
		} else {
			if ($this->_isRest()) {
				return $this->RestResponse->describe('Sightings', 'add', false, $this->response->type());
			}
			if (!$this->request->is('ajax')) {
				throw new MethodNotAllowedException('This method is only accessible via POST requests and ajax GET requests.');
			} else {
				$this->layout = false;
				$this->loadModel('Attribute');
				$attributes = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id)));
				if (empty($attributes)) {
					throw new MethodNotAllowedExeption('Invalid Attribute.');
				}
				$this->set('event_id', $attributes[0]['Attribute']['event_id']);
				$this->set('id', $id);
				$this->render('ajax/add_sighting');
			}
		}
	}

	public function advanced($id, $context = 'attribute') {
		if (empty($id)) {
			throw new MethodNotAllowedException('Invalid ' . $context . '.');
		}
		$input_id = $id;
		$id = $this->Sighting->explodeIdList($id);
		if ($context == 'attribute') {
			$this->loadModel('Attribute');
			$attributes = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id), 'flatten' => 1));
			if (empty($attributes)) {
				throw new MethodNotAllowedException('Invalid attribute.');
			}
		} else {
			$this->loadModel('Event');
			$events = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id, 'metadata' => true));
			if (empty($events)) {
				throw new MethodNotAllowedException('Invalid event.');
			}
		}
		$this->set('context', $context);
		$this->set('id', $input_id);
		$this->render('/Sightings/ajax/advanced');
	}

	public function quickDelete($id, $rawId, $context) {
		if (!$this->userRole['perm_modify_org']) throw new MethodNotAllowedException('You are not authorised to remove sightings data as you don\'t have permission to modify your organisation\'s data.');
		if (!$this->request->is('post')) {
			$this->set('id', $id);
			$sighting = $this->Sighting->find('first', array('conditions' => array('Sighting.id' => $id), 'recursive' => -1, 'fields' => array('Sighting.attribute_id')));
			$this->set('rawId', $rawId);
			$this->set('context', $context);
			$this->render('ajax/quickDeleteConfirmationForm');
		} else {
			if (!isset($id)) {
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => 'Invalid request.')), 'status' => 200, 'type' => 'json'));
			} else {
				$sighting = $this->Sighting->find('first', array('conditions' => array('Sighting.id' => $id), 'recursive' => -1));
				if (empty($sighting)) {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => 'Invalid sighting.')), 'status' => 200, 'type' => 'json'));
				}
				if (!$this->_isSiteAdmin() && $sighting['Sighting']['org_id'] != $this->Auth->user('org_id')) {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => 'Invalid sighting.')), 'status' => 200, 'type' => 'json'));
				}
				$result = $this->Sighting->delete($id);
				if ($result) {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Sighting deleted.')), 'status' => 200, 'type' => 'json'));
				} else {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => 'Sighting could not be deleted')), 'status' => 200, 'type' => 'json'));
				}
			}
		}
	}

	// takes a sighting ID
	public function delete($id) {
		if (!$this->userRole['perm_modify_org']) throw new MethodNotAllowedException('You are not authorised to remove sightings data as you don\'t have permission to modify your organisation\'s data.');
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This action can only be accessed via a post request.');
		$sighting = $this->Sighting->find('first', array('conditions' => array('Sighting.id' => $id), 'recursive' => -1));
		if (empty($sighting)) throw new NotFoundException('Invalid sighting.');
		if (!$this->_isSiteAdmin()) {
			if ($sighting['Sighting']['org_id'] != $this->Auth->user('org_id')) throw new NotFoundException('Invalid sighting.');
		}
		$result = $this->Sighting->delete($sighting['Sighting']['id']);
		if (!$result) {
			return $this->RestResponse->saveFailResponse('Sighting', 'delete', $id, 'Could not delete the Sighting.');
		} else {
			return $this->RestResponse->saveSuccessResponse('Sighting', 'delete', $id, false, 'Sighting successfuly deleted.');
		}
	}

	public function index($eventid = false) {
		$this->loadModel('Event');
		$sightingConditions = array();
		if ($eventid) {
			$sightingConditions = array('Sighting.event_id' => $eventid);
		}
		$sightedEvents = $this->Sighting->find('list', array(
			'group' => 'Sighting.event_id',
			'fields' => array('Sighting.event_id'),
			'conditions' => $sightingConditions
		));
		if (empty($sightedEvents)) {
			$this->RestResponse->viewData(array());
		}
		$conditions = array('metadata' => true, 'contain' => false);
		if ($eventid) {
			$conditions['eventid'] = $sightedEvents;
		}
		$events = $this->Event->fetchEventIds($this->Auth->user(), false, false, false, false, false, false, $sightedEvents);
		$sightings = array();
		if (!empty($events)) {
			foreach ($events as $k => $event) {
				$sightings = array_merge($sightings, $this->Sighting->attachToEvent($event, $this->Auth->user()));
			}
		}
		return $this->RestResponse->viewData($sightings);
	}

	public function listSightings($id, $context = 'attribute', $org_id = false) {
		$this->loadModel('Event');
		$rawId = $id;
		$id = $this->Sighting->explodeIdList($id);
		if ($context === 'attribute') {
			$object = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id, 'Attribute.deleted' => 0), 'flatten' => 1));
		} else {
			// let's set the context to event here, since we reuse the variable later on for some additional lookups.
			// Passing $context = 'org' could have interesting results otherwise...
			$context = 'event';
			$object = $this->Event->fetchEvent($this->Auth->user(), $options = array('eventid' => $id, 'metadata' => true));
		}
		if (empty($object)) {
			throw new MethodNotAllowedException('Invalid object.');
		}
		$conditions = array(
			'Sighting.' . $context . '_id' => $id
		);
		if ($org_id) {
			$conditions[] = array('Sighting.org_id' => $org_id);
		}
		$sightings = $this->Sighting->find('all', array(
			'conditions' => $conditions,
			'recursive' => -1,
			'contain' => array('Organisation.name'),
			'order' => array('Sighting.date_sighting DESC')
		));
		$this->set('org_id', $org_id);
		$this->set('rawId', $rawId);
		$this->set('context', $context);
		$this->set('types', array('Sighting', 'False-positive', 'Expiration'));
		if (Configure::read('Plugin.Sightings_anonymise') && !$this->_isSiteAdmin()) {
			foreach ($sightings as $k => $v) {
				if ($v['Sighting']['org_id'] != $this->Auth->user('org_id')) {
					$sightings[$k]['Organisation']['name'] = '';
					$sightings[$k]['Sighting']['org_id'] = 0;
				}
			}
		}
		$this->set('sightings', $sightings);
		$this->layout = false;
		$this->render('ajax/list_sightings');
	}

	public function viewSightings($id, $context = 'attribute') {
		$this->loadModel('Event');
		$id = $this->Sighting->explodeIdList($id);
		if ($context === 'attribute') {
			$attribute_id = $id;
			$object = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id, 'Attribute.deleted' => 0), 'flatten' => 1));
			if (empty($object)) {
				throw new MethodNotAllowedException('Invalid object.');
			}
			$eventIds = array();
			foreach ($object as $k => $v) {
				$eventIds[] = $v['Attribute']['event_id'];
			}
			$events = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $eventIds));
		} else {
			$attribute_id = false;
			// let's set the context to event here, since we reuse the variable later on for some additional lookups.
			// Passing $context = 'org' could have interesting results otherwise...
			$context = 'event';
			$events = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));

		}
		if (empty($events)) {
			throw new MethodNotAllowedException('Invalid object.');
		}
		$results = array();
		$raw = array();
		foreach ($events as $event) {
			$raw = array_merge($raw, $this->Sighting->attachToEvent($event, $this->Auth->user(), $attribute_id));
		}
		foreach ($raw as $sighting) {
			$results[$sighting['type']][date('Ymd', $sighting['date_sighting'])][] = $sighting;
		}
		$tsv = 'date\tSighting\tFalse-positive\n';
		$dataPoints = array();
		$startDate = (date('Ymd'));
		$details = array();
		$range = (!empty(Configure::read('MISP.Sightings_range')) && is_numeric(Configure::read('MISP.Sightings_range'))) ? Configure::read('MISP.Sightings_range') : 365;
		$range = date('Ymd', strtotime("-" . $range . " days", time()));
		foreach ($results as $type => $data) {
			foreach ($data as $date => $sighting) {
				if ($date < $startDate) {
					if ($date >= $range) {
						$startDate = $date;
					}
				}
				$temp = array();
				foreach ($sighting as $sightingInstance) {
					if (!isset($sightingInstance['Organisation']['name'])) {
						$org = 'Anonymised';
					} else {
						$org = $sightingInstance['Organisation']['name'];
					}
					$temp[$org] = isset($temp[$org]) ? $temp[$org] + 1 : 1;
				}
				$dataPoints[$date][$type] = array('count' => count($sighting), 'details' => $temp);
			}
		}
		$startDate = date('Ymd',strtotime("-3 days", strtotime($startDate)));
		for ($i = $startDate; $i < date('Ymd') + 1; $i++) {
			if (checkdate(substr($i, 4, 2), substr($i, 6, 2), substr($i, 0, 4))) {
				$tsv .= $i . '\t' . (isset($dataPoints[$i][0]['count']) ? $dataPoints[$i][0]['count'] : 0) . '\t' . (isset($dataPoints[$i][1]['count']) ? $dataPoints[$i][1]['count'] : 0) . '\n';
				$details[$i][0] = isset($dataPoints[$i][0]['details']) ? $dataPoints[$i][0]['details'] : array();
				$details[$i][1] = isset($dataPoints[$i][1]['details']) ? $dataPoints[$i][1]['details'] : array();
			}
		}
		$this->set('tsv', $tsv);
		$this->set('results', $results);
		$this->layout = 'ajax';
		$this->render('ajax/view_sightings');
	}
}
