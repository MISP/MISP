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
		$error = false;
		// If we have received a POST request
		if ($this->request->is('post')) {
			if (isset($this->request->data['request'])) {
				$this->request->data = $this->request->data['request'];
			}
			if (!isset($this->request->data['Attribute'])) {
				$this->request->data = array('Attribute' => $this->request->data);
			}
			$object = $this->Object->attributeCleanup($this->request->data);
			// we pre-validate the attributes before we create an object at this point
			// This allows us to stop the process and return an error (API) or return
			//  to the add form
			foreach ($object['Attribute'] as $k => $attribute) {
				$object['Attribute'][$k]['event_id'] = $eventId;
				$this->Object->Event->Attribute->set($attribute);
				if (!$this->Object->Event->Attribute->validates()) {
					$error = 'Could not save object as at least one attribute has failed validation (' . $attribute['object_relation'] . '). ' . json_encode($this->Object->Event->Attribute->validationErrors);
				}
			}
			if (empty($error)) {
				$error = $this->Object->ObjectTemplate->checkTemplateConformity($template, $object);
				if ($error === true) {
						$result = $this->Object->saveObject($object, $eventId, $template, $this->Auth->user(), $errorBehaviour = 'halt');
				}
				if ($this->_isRest()) {
					if (is_numeric($result)) {
						$object = $this->Object->find('first', array(
							'recursive' => -1,
							'conditions' => array('Object.id' => $result),
							'contain' => array('Attribute')
						));
						return $this->RestResponse->viewData($object, $this->response->type());
					} else {
						return $this->RestResponse->saveFailResponse('Attributes', 'add', false, $result, $this->response->type());
					}
				} else {
					 $this->Session->setFlash('Object saved.');
					 $this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
				}
			}
		}

		// In the case of a GET request or if the object could not be validated, show the form / the requirement
		if ($this->_isRest()) {
			if ($error) {

			} else {
				return $this->RestResponse->viewData($orgs, $this->response->type());
			}
		} else {
			if (!empty($error)) {
				$this->Session->setFlash($error);
			}
			$template = $this->Object->prepareTemplate($template);
			$enabledRows = array_keys($template['ObjectTemplateElement']);
			$this->set('enabledRows', $enabledRows);
			$distributionData = $this->Object->Event->Attribute->fetchDistributionData($this->Auth->user());
			$this->set('distributionData', $distributionData);
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
