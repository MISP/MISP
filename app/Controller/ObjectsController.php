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

	/**
   * Create an object using a template
	 * POSTing will take the input and validate it against the template
	 * GETing will return the template
	 */
  public function add($eventId, $templateId = false) {
		if (!$this->userRole['perm_modify']) {
			throw new MethodNotAllowedException('You don\'t have permissions to create objects.');
		}
		$eventFindParams = array(
			'recursive' => -1,
			'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id'),
			'conditions' => array('Event.id' => $eventId)
		);

		// Find the event that is to be updated
		if (Validation::uuid($eventId)) {
			$eventFindParams['conditions']['Event.uuid'] = $eventId;
		} else if (is_numeric($eventId)) {
			$eventFindParams['conditions']['Event.id'] = $eventId;
		} else {
			throw new NotFoundException('Invalid event.');
		}
		$event = $this->Object->Event->find('first', $eventFindParams);
		if (empty($event) || (!$this->_isSiteAdmin() &&	$event['Event']['orgc_id'] != $this->Auth->user('org_id'))) {
			throw new NotFoundException('Invalid event.');
		}
		$eventId = $event['Event']['id'];
		$template = $this->Object->ObjectTemplate->find('first', array(
			'conditions' => array('ObjectTemplate.id' => $templateId),
			'recursive' => -1,
			'contain' => array(
				'ObjectTemplateElement'
			)
		));
		$eventId = $event['Event']['id'];

		// If we have received a POST request
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
		}

		// In the case of a GET request or if the object could not be validated, show the form / the requirement
		if ($this->_isRest()) {
			return $this->RestResponse->viewData($orgs, $this->response->type());
		} else {
			$template = $this->Object->prepareTemplate($template);
			//debug($template);
			$this->set('event', $event);
			$this->set('ajax', false);
			$this->set('template', $template);
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
