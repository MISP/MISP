<?php
App::uses('AppController', 'Controller');

class EventNetworkHistoryController extends AppController {

	public $components = array(
			'Security',
			'RequestHandler'
	);

	public function beforeFilter() {
		parent::beforeFilter();
	}

	public function get($event_id = false) {
		if (!$this->request->is('get')) {
			throw new MethodNotAllowedException(__('Invalid method.'));
		}
		if ($event_id === false) throw new MethodNotAllowedException(__('No event ID set.'));
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException(__('You don\'t have permissions to add a new network'));
		}

		// retreive current org_id
		$org_id = $this->_checkOrg();

		// validate event
		$this->loadModel('Event');
		if (Validation::uuid($event_id)) {
			$temp = $this->Event->find('first', array('recursive' => -1, 'fields' => array('Event.id'), 'conditions' => array('Event.uuid' => $event_id)));
			if (empty($temp)) throw new NotFoundException(__('Invalid event'));
			$event_id = $temp['Event']['id'];
		} else if (!is_numeric($event_id)) {
			throw new NotFoundException(__('Invalid event'));
		}
		$this->Event->id = $event_id;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}

		$this->Event->read(null, $event_id);
		if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
			throw new UnauthorizedException(__('You do not have permission to do that.'));
		}

		// fetch networks
		$networks = $this->EventNetworkHistory->find('all', array(
			'conditions' => array(
				'EventNetworkHistory.event_id' => $event_id,
				'EventNetworkHistory.org_id' => $org_id
			),
			'contain' => array(
				'User' => array(
					'conditions' => array(
						'User.id = EventNetworkHistory.user_id'
					),
					'fields' => array(
						'User.email'
					)
				)
			)
		));
		return $this->RestResponse->viewData($networks, $this->response->type());
	}

	public function add($event_id = false) {
		if ($this->request->is('get') && $this->_isRest()) {
			return $this->RestResponse->describe('NetworkHistory', 'add', false, $this->response->type());
		} else if ($this->request->is('get')) { // retreive form
			//throw new MethodNotAllowedException(__('Invalid method.'));
			$formURL = 'eventNetworkHistory_add_form';

			if (!$this->_isSiteAdmin()) {
				if ($networkHistory['org_id'] == $this->Auth->user('org_id')
				&& (($this->userRole['perm_modify'] && $networkHistory['user_id'] != $this->Auth->user('id'))
						|| $this->userRole['perm_modify_org'])) {
					// Allow the edit
				} else {
					throw new NotFoundException(__('Invalid network history'));
				}
			}

			$this->set('action', 'add');
			$this->set('event_id', $event_id);
			$this->render('ajax/' . $formURL);

		} else {
			if ($event_id === false) throw new MethodNotAllowedException(__('No event ID set.'));
			if (!$this->userRole['perm_add']) {
				throw new MethodNotAllowedException(__('You don\'t have permissions to add a new network'));
			}
			$this->loadModel('Event');
			if (Validation::uuid($event_id)) {
				$temp = $this->Event->find('first', array('recursive' => -1, 'fields' => array('Event.id'), 'conditions' => array('Event.uuid' => $event_id)));
				if (empty($temp)) throw new NotFoundException(__('Invalid event'));
				$event_id = $temp['Event']['id'];
			} else if (!is_numeric($event_id)) {
				throw new NotFoundException(__('Invalid event'));
			}
			$this->Event->id = $event_id;
			if (!$this->Event->exists()) {
				throw new NotFoundException(__('Invalid event'));
			}

			$networkHistory = array();
			$this->Event->read(null, $event_id);
			if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
				throw new UnauthorizedException(__('You do not have permission to do that.'));
			} else {
				$networkHistory['EventNetworkHistory']['event_id'] = $event_id;
			}

			$date = new DateTime();
			if (!isset($this->request->data['EventNetworkHistory']['network_json'])) {
				throw new MethodNotAllowedException('No network data set');
			} else {
				$networkHistory['EventNetworkHistory']['network_json'] = $this->request->data['EventNetworkHistory']['network_json'];
			}
			if (!isset($this->request->data['EventNetworkHistory']['network_name'])) {
				$networkHistory['EventNetworkHistory']['network_name'] = null;
			} else {
				$networkHistory['EventNetworkHistory']['network_name'] = $this->request->data['EventNetworkHistory']['network_name'];
			}
			$networkHistory['EventNetworkHistory']['timestamp'] = $date->getTimestamp();

			// Network pushed will be the owner of the authentication key
			$networkHistory['EventNetworkHistory']['user_id'] = $this->Auth->user('id');
			$networkHistory['EventNetworkHistory']['org_id'] = $this->Auth->user('org_id');

			$result = $this->EventNetworkHistory->save($networkHistory, true, array(
				'event_id',
				'network_json',
				'network_name',
				'timestamp',
				'user_id',
				'org_id'
				)
			);
			if ($result) {
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Network history saved.')), 'status'=>200, 'type' => 'json'));
			} else {
				return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Network history could not be saved.')), 'status'=>200, 'type' => 'json'));
			}
		}
	}

	public function edit($id) {
		$this->EventNetworkHistory->edit();
	}

	public function delete($id) {
		if (!$this->request->is('post')) {
			$this->set('id', $id);
			$conditions = array('id' => $id);
			$networkHistory = $this->EventNetworkHistory->find('first', array(
					'conditions' => $conditions,
					'recursive' => -1,
					'fields' => array('id', 'event_id'),
			));
			$this->render('ajax/eventNetworkHistory_delete_form');
		} else {
			$this->set('id', $id);
			$conditions = array('id' => $id);
			$networkHistory = $this->EventNetworkHistory->find('first', array(
					'conditions' => $conditions,
					'recursive' => -1,
					'fields' => array('id', 'event_id'),
			));
			if (empty($networkHistory)) throw new NotFoundException('Invalid NetworkHistory');
			if ($this->request->is('ajax')) {
				if ($this->request->is('post')) {
					$result = $this->EventNetworkHistory->delete($id);
					if ($result) {
						return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Network history deleted.')), 'status'=>200, 'type' => 'json'));
					} else {
						return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Network history was not deleted.')), 'status'=>200, 'type' => 'json'));
					}
				}
			}
		}
	}

	public function fetchForm($action, $event_id, $id = null) {
		$formURL = 'eventNetworkHistory_add_form';
		if ($action == 'edit') {
			$params = array(
				'conditions' => array('EventNetworkHistory.id' => $id),
				'flatten' => 1,
			);
			//$networkHistory = $this->NetworkHistory->fetchNetworkHistory($this->Auth->user(), $params);
			$networkHistory = $this->NetworkHistory->get($this->Auth->user(), $params);
			if (empty($networkHistory)) throw new NotFoundException(__('Invalid network history'));
			$networkHistory = $networkHistory[0];
			$this->set('networkHistory', $networkHistory);
			$formURL = 'eventNetworkHistory_add_form';
		} else if ($action == 'delete') {
			$params = array(
				'conditions' => array('EventNetworkHistory.id' => $id),
				'flatten' => 1,
			);
			//$networkHistory = $this->NetworkHistory->fetchNetworkHistory($this->Auth->user(), $params);
			$networkHistory = $this->NetworkHistory->get($this->Auth->user(), $params);
			if (empty($networkHistory)) throw new NotFoundException(__('Invalid network history'));
			$networkHistory = $networkHistory[0];
			$this->set('networkHistory', $networkHistory);
			$formURL = 'eventNetworkHistory_delete_form';
		}

		if (!$this->_isSiteAdmin()) {
			if ($networkHistory['org_id'] == $this->Auth->user('org_id')
			&& (($this->userRole['perm_modify'] && $networkHistory['user_id'] != $this->Auth->user('id'))
					|| $this->userRole['perm_modify_org'])) {
				// Allow the edit
			} else {
				throw new NotFoundException(__('Invalid network history'));
			}
		}

		$this->set('action', $action);
		$this->set('event_id', $event_id);

		$this->render('ajax/' . $formURL);
	}
}
