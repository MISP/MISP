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

	public function get($event_id = null, $org_id = null) {
		$networks = $this->EventNetworkHistory->find('all', array(
			'conditions' => array(),
			'fields' => array()
		));
		return $this->RestResponse->viewData($networks, $this->response->type());
	}

	public function add($event_id = false) {
		if ($this->request->is('get') && $this->_isRest()) {
			return $this->RestResponse->describe('NetworkHistory', 'add', false, $this->response->type());
		} else if ($this->request->is('get')) {
			throw new MethodNotAllowedException(__('Invalid method.'));
		}
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

		$this->Event->read(null, $event_id);
		if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
			throw new UnauthorizedException(__('You do not have permission to do that.'));
		}

		$date = new DateTime();
		$networkHistory = $this->request->data['EventNetworkHistory'];
		if (!isset($this->request->data['EventNetworkHistory']['network_json'])) {
			throw new MethodNotAllowedException('No network data set');
		}
		if (!isset($this->request->data['EventNetworkHistory']['network_name'])) {
			$networkHistory['EventNetworkHistory']['network_name'] = null;
		}
		$networkHistory['EventNetworkHistory']['timestamp'] = $date->getTimestamp();

		// Network pushed will be the owner of the authentication key
		$networkHistory['EventNetworkHistory']['user_id'] = $this->Auth->user('id');
		$networkHistory['EventNetworkHistory']['org_id'] = $this->Auth->user('org_id');

		$result = $this->EventNetworkHistory->save($networkHistory);
		if ($result) {
			return $this->RestResponse->saveSuccessResponse('NetworkHistory', 'save', $event_id, $this->response->type(), __("Network history saved"));
		} else {
			return $this->RestResponse->saveFailResponse('NetworkHistory', 'save', false, __("Network history could not be saved"), $this->response->type());
		}
	}

	public function edit($id) {
		$this->EventNetworkHistory->edit();
	}

	public function delete($id) {
		$this->EventNetworkHistory->delete();
	}

	public function fetchForm($action, $event_id, $id = null) {
		if ($action == 'edit') {
			$params = array(
				'conditions' => array('EventNetworkHistory.id' => $id),
				'flatten' => 1,
			);
			$networkHistory = $this->NetworkHistory->fetchNetworkHistory($this->Auth->user(), $params);
			if (empty($networkHistory)) throw new NotFoundException(__('Invalid network history'));
			$networkHistory = $networkHistory[0];
			$this->set('networkHistory', $networkHistory);
		}
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

		$this->set('action', $action);
		$this->set('event_id', $event_id);

		$this->render('ajax/' . $formURL);
	}

	public function fetchNetworkHistory($user, $params) {
		return 1;
	}
}
