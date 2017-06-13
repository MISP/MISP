<?php

App::uses('AppController', 'Controller');

class ObjectsController extends AppController {
	public $components = array('Security' ,'RequestHandler', 'Session');

	public $paginate = array(
			'limit' => 20,
			'order' => array(
					'Object.id' => 'desc'
			),
	);

  public function add($eventId, $templateId = false) {
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException('You don\'t have permissions to create objects.');
		}
		if (Validation::uuid($eventId)) {
			$lookupField = 'uuid';
		} else if (!is_numeric($eventId)) {
			$lookupField = 'id';
			throw new NotFoundException('Invalid event.');
		}
		$event = $this->Object->Event->find('first', array(
			'recursive' => -1,
			'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id'),
			'conditions' => array('Event.id' => $eventId)
		));
		if (empty($event)) {
			throw new NotFoundException('Invalid event.');
		}
		$eventId = $event['Event']['id'];
		if (!$this->_isSiteAdmin() && ($event['Event']['orgc_id'] != $this->Auth->user('org_id') || !$this->userRole['perm_modify'])) {
			throw new UnauthorizedException('You do not have permission to do that.');
		}
		if ($this->request->is('post')) {
			if (isset($this->request->data['request'])) {
				$this->request->data = $this->request->data['request'];
			}
			if (!isset($this->request->data['Object'])) {
				$this->request->data = array('Object' => $this->request->data);
			}
			$templateCheckResult = $this->Object->ObjectTemplate->checkTemplateConformity($templateId, $this->request->data);
			if (!$templateCheckResult) {
				throw new MethodNotAllowedException('Object does not meet the template requirements');
			}
			$this->Object->saveObject($this->request->data, $eventId, $errorBehaviour = 'halt');
		} else {

		}
  }

  public function edit($id) {

  }

  public function delete($id) {
		if (!$this->userRole['perm_modify']) {
			throw new MethodNotAllowedException('You don\'t have permissions to delete objects.');
		}
		if (Validation::uuid($eventId)) {
			$lookupField = 'uuid';
		} else if (!is_numeric($eventId)) {
			$lookupField = 'id';
			throw new NotFoundException('Invalid event.');
		}
		$event = $this->Object->Event->find('first', array(
			'recursive' => -1,
			'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id'),
			'conditions' => array('Event.id' => $eventId)
		));
		if (empty($event)) {
			throw new NotFoundException('Invalid event.');
		}
		$eventId = $event['Event']['id'];
		if (!$this->_isSiteAdmin() && ($event['Event']['orgc_id'] != $this->Auth->user('org_id') || !$this->userRole['perm_modify'])) {
			throw new UnauthorizedException('You do not have permission to do that.');
		}
		$this->Object->delete($id);
  }

  public function view($id) {
		if ($this->_isRest()) {
			$objects = $this->Object->fetchObjects($this->Auth->user(), array('conditions' => array('Object.id' => $id)));
			if (!empty($objects)) {
				return $this->RestResponse->viewData($objects, $this->response->type());
			}
		}
  }
}
