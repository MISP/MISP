<?php

App::uses('AppController', 'Controller');

class ObjectsController extends AppController {
	var $uses = 'MispObject';

	public $components = array('Security' ,'RequestHandler', 'Session');

	public $paginate = array(
			'limit' => 20,
			'order' => array(
					'Object.id' => 'desc'
			),
	);

	public function beforeFilter() {
		parent::beforeFilter();
		$this->Security->unlockedActions = array('revise_object', 'get_row');
	}

	public function revise_object($action, $event_id, $template_id, $object_id = false) {
		if (!$this->request->is('post') && !$this->request->is('put')) {
			throw new MethodNotAllowedException('This action can only be reached via POST requests');
		}
		$this->request->data = $this->MispObject->attributeCleanup($this->request->data);
		$eventFindParams = array(
			'recursive' => -1,
			'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id'),
			'conditions' => array('Event.id' => $event_id)
		);
		$template = $this->MispObject->ObjectTemplate->find('first', array(
			'conditions' => array('ObjectTemplate.id' => $template_id),
			'recursive' => -1,
			'contain' => array(
				'ObjectTemplateElement'
			)
		));
		$event = $this->MispObject->Event->find('first', $eventFindParams);
		if (empty($event) || (!$this->_isSiteAdmin() &&	$event['Event']['orgc_id'] != $this->Auth->user('org_id'))) {
			throw new NotFoundException('Invalid event.');
		}
		$sharing_groups = array();
		if ($this->request->data['Object']['distribution'] == 4) {
			$sharing_groups[$this->request->data['Object']['sharing_group_id']] = false;
		}
		foreach ($this->request->data['Attribute'] as $attribute) {
			if ($attribute['distribution'] == 4) {
				$sharing_groups[$attribute['sharing_group_id']] = false;
			}
		}
		if (!empty($sharing_groups)) {
			$sgs = $this->MispObject->SharingGroup->find('all', array(
				'conditions' => array('SharingGroup.id' => array_keys($sharing_groups)),
				'recursive' => -1,
				'fields' => array('SharingGroup.id', 'SharingGroup.name'),
				'order' => false
			));
			foreach ($sgs as $sg) {
				$sharing_groups[$sg['SharingGroup']['id']] = $sg;
			}
			foreach ($sharing_groups as $k => $sg) {
				if (empty($sg)) throw new NotFoundException('Invalid sharing group.');
			}
			$this->set('sharing_groups', $sharing_groups);
		}
		if ($this->request->data['Object']['distribution'] == 4) {
			$sg = $this->MispObject->SharingGroup->find('first', array(
				'conditions' => array('SharingGroup.id' => $this->request->data['Object']['sharing_group_id']),
				'recursive' => -1,
				'fields' => array('SharingGroup.id', 'SharingGroup.name'),
				'order' => false
			));
			if (empty($sg)) throw new NotFoundException('Invalid sharing group.');
			$this->set('sg', $sg);
		}
		$this->set('distributionLevels', $this->MispObject->Attribute->distributionLevels);
		$this->set('action', $action);
		$this->set('template', $template);
		$this->set('object_id', $object_id);
		$this->set('event', $event);
		$this->set('data', $this->request->data);
	}


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
		$event = $this->MispObject->Event->find('first', $eventFindParams);
		if (empty($event) || (!$this->_isSiteAdmin() &&	$event['Event']['orgc_id'] != $this->Auth->user('org_id'))) {
			throw new NotFoundException('Invalid event.');
		}
		$eventId = $event['Event']['id'];
		$templates = $this->MispObject->ObjectTemplate->find('all', array(
			'conditions' => array('ObjectTemplate.id' => $templateId),
			'recursive' => -1,
			'contain' => array(
				'ObjectTemplateElement'
			)
		));
		$template_version = false;
		$template = false;
		foreach ($templates as $temp) {
			if (!empty($template_version)) {
				if (intval($template['ObjectTemplate']['version']) > intval($template_version)) {
					$template = $temp;
				}
			} else {
				$template = $temp;
			}
		}
		$error = false;
		if (empty($template)) {
			$error = 'No valid template found to edit the object.';
		}
		// If we have received a POST request
		if ($this->request->is('post')) {
			if (isset($this->request->data['request'])) {
				$this->request->data = $this->request->data['request'];
			}
			if (isset($this->request->data['Object']['data'])) {
				$this->request->data = json_decode($this->request->data['Object']['data'], true);
			}
			if (!isset($this->request->data['Object'])) {
				$this->request->data = array('Object' => $this->request->data);
			}
			if (!isset($this->request->data['Attribute']) && isset($this->request->data['Object']['Attribute'])) {
				$this->request->data['Attribute'] = $this->request->data['Object']['Attribute'];
				unset($this->request->data['Object']['Attribute']);
			}
			$object = $this->MispObject->attributeCleanup($this->request->data);
			// we pre-validate the attributes before we create an object at this point
			// This allows us to stop the process and return an error (API) or return
			//  to the add form
			if (empty($object['Attribute'])) {
				$error = 'Could not save the object as no attributes were set.';
			} else {
				foreach ($object['Attribute'] as $k => $attribute) {
					$object['Attribute'][$k]['event_id'] = $eventId;
					$this->MispObject->Event->Attribute->set($attribute);
					if (!$this->MispObject->Event->Attribute->validates()) {
						$error = 'Could not save object as at least one attribute has failed validation (' . $attribute['object_relation'] . '). ' . json_encode($this->MispObject->Event->Attribute->validationErrors);
					}
				}
			}
			if (empty($error)) {
				$error = $this->MispObject->ObjectTemplate->checkTemplateConformity($template, $object);
				if ($error === true) {
					$result = $this->MispObject->saveObject($object, $eventId, $template, $this->Auth->user(), $errorBehaviour = 'halt');
					if ($result) $this->MispObject->Event->unpublishEvent($eventId);
				} else {
					$result = false;
				}
				if ($this->_isRest()) {
					if (is_numeric($result)) {
						$object = $this->MispObject->find('first', array(
							'recursive' => -1,
							'conditions' => array('Object.id' => $result),
							'contain' => array('Attribute')
						));
						return $this->RestResponse->viewData($object, $this->response->type());
					} else {
						return $this->RestResponse->saveFailResponse('Objects', 'add', false, $error, $this->response->type());
					}
				} else {
					if (is_numeric($result)) {
						$this->Session->setFlash('Object saved.');
						$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
					}
				}
			}
		}

		// In the case of a GET request or if the object could not be validated, show the form / the requirement
		if ($this->_isRest()) {
			if ($error) {
				return $this->RestResponse->saveFailResponse('objects', 'add', $eventId . '/' . $templateId, $error, $this->response->type());
			} else {
				return $this->RestResponse->viewData($orgs, $this->response->type());
			}
		} else {
			if (!empty($error)) {
				$this->Session->setFlash($error);
			}
			$template = $this->MispObject->prepareTemplate($template, $this->request->data);
			$enabledRows = array_keys($template['ObjectTemplateElement']);
			$this->set('enabledRows', $enabledRows);
			$distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($this->Auth->user());
			$this->set('distributionData', $distributionData);
			$this->set('event', $event);
			$this->set('ajax', false);
			$this->set('action', 'add');
			$this->set('template', $template);
		}
  }

	public function get_row($template_id, $object_relation, $k) {
		$template = $this->MispObject->ObjectTemplate->find('first', array(
			'conditions' => array('ObjectTemplate.id' => $template_id),
			'recursive' => -1,
			'contain' => array(
				'ObjectTemplateElement'
			)
		));
		$template = $this->MispObject->prepareTemplate($template);
		$element = array();
		foreach ($template['ObjectTemplateElement'] as $templateElement) {
			if ($templateElement['object_relation'] == $object_relation) {
				$element = $templateElement;
			}
		}
		$distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($this->Auth->user());
		$this->layout = false;
		$this->set('distributionData', $distributionData);
		$this->set('k', $k);
		$this->set('element', $element);
	}

  public function edit($id) {
		if (!$this->userRole['perm_modify']) {
			throw new MethodNotAllowedException('You don\'t have permissions to edit objects.');
		}
		$object = $this->MispObject->find('first', array(
			'conditions' => array('Object.id' => $id),
			'recursive' => -1,
			'contain' => array(
				'Attribute' => array(
					'conditions' => array(
						'Attribute.deleted' => 0
					)
				)
			)
		));
		if (empty($object)) {
			throw new NotFoundException('Invalid object.');
		}
		$eventFindParams = array(
			'recursive' => -1,
			'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id'),
			'conditions' => array('Event.id' => $object['Object']['event_id'])
		);

		$event = $this->MispObject->Event->find('first', $eventFindParams);
		if (empty($event) || (!$this->_isSiteAdmin() &&	$event['Event']['orgc_id'] != $this->Auth->user('org_id'))) {
			throw new NotFoundException('Invalid object.');
		}
		$template = $this->MispObject->ObjectTemplate->find('first', array(
			'conditions' => array(
				'ObjectTemplate.uuid' => $object['Object']['template_uuid'],
				'ObjectTemplate.version' => $object['Object']['template_version'],
			),
			'recursive' => -1,
			'contain' => array(
				'ObjectTemplateElement'
			)
		));
		if (empty($template)) {
			$this->Session->setFlash('Object cannot be edited, no valid template found.');
			$this->redirect(array('controller' => 'events', 'action' => 'view', $object['Object']['event_id']));
		}
		$template = $this->MispObject->prepareTemplate($template, $object);
		$enabledRows = false;

		if ($this->request->is('post') || $this->request->is('put')) {
			if (isset($this->request->data['request'])) {
				$this->request->data = $this->request->data['request'];
			}
			if (isset($this->request->data['Object']['data'])) {
				$this->request->data = json_decode($this->request->data['Object']['data'], true);
			}
			if (!isset($this->request->data['Attribute'])) {
				$this->request->data = array('Attribute' => $this->request->data);
			}
			$objectToSave = $this->MispObject->attributeCleanup($this->request->data);
			$objectToSave = $this->MispObject->deltaMerge($object, $objectToSave);
			// we pre-validate the attributes before we create an object at this point
			// This allows us to stop the process and return an error (API) or return
			//  to the add form
			if (empty($error)) {
				if ($this->_isRest()) {
					if (is_numeric($objectToSave)) {
						$objectToSave = $this->MispObject->find('first', array(
							'recursive' => -1,
							'conditions' => array('Object.id' => $result),
							'contain' => array('Attribute')
						));
						$this->MispObject->Event->unpublishEvent($object['Object']['event_id']);
						return $this->RestResponse->viewData($objectToSave, $this->response->type());
					} else {
						return $this->RestResponse->saveFailResponse('Objects', 'add', false, $result, $this->response->type());
					}
				} else {
					$this->MispObject->Event->unpublishEvent($object['Object']['event_id']);
					$this->Session->setFlash('Object saved.');
					$this->redirect(array('controller' => 'events', 'action' => 'view', $object['Object']['event_id']));
				}
			}
		} else {
			$enabledRows = array();
			$this->request->data['Object'] = $object['Object'];
			foreach ($template['ObjectTemplateElement'] as $k => $element) {
				foreach ($object['Attribute'] as $k2 => $attribute) {
					if ($attribute['object_relation'] == $element['object_relation']) {
						$enabledRows[] = $k;
						$this->request->data['Attribute'][$k] = $attribute;
						if (!empty($element['values_list'])) {
							$this->request->data['Attribute'][$k]['value_select'] = $attribute['value'];
						} else {
							if (!empty($element['sane_default'])) {
								if (in_array($attribute['value'], $element['sane_default'])) {
									$this->request->data['Attribute'][$k]['value_select'] = $attribute['value'];
								} else {
									$this->request->data['Attribute'][$k]['value_select'] = 'Enter value manually';
								}
							}
						}
					}
				}
			}

		}
		$this->set('enabledRows', $enabledRows);
		$distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($this->Auth->user());
		$this->set('distributionData', $distributionData);
		$this->set('event', $event);
		$this->set('ajax', false);
		$this->set('template', $template);
		$this->set('action', 'edit');
		$this->set('object', $object);
		$this->render('add');
  }

	public function addValueField() {

	}

  public function delete($id, $hard = false) {
		if (!$this->userRole['perm_modify']) {
			throw new MethodNotAllowedException('You don\'t have permissions to delete objects.');
		}
		if (Validation::uuid($id)) {
			$lookupField = 'uuid';
		} else if (!is_numeric($id)) {
			$lookupField = 'id';
			throw new NotFoundException('Invalid object.');
		}
		$object = $this->MispObject->find('first', array(
			'recursive' => -1,
			'fields' => array('Object.id', 'Object.event_id', 'Event.id', 'Event.uuid', 'Event.orgc_id'),
			'conditions' => array('Object.id' => $id),
			'contain' => array(
				'Event'
			)
		));
		if (empty($object)) {
			throw new NotFoundException('Invalid event.');
		}
		$eventId = $object['Event']['id'];
		if (!$this->_isSiteAdmin() && ($object['Event']['orgc_id'] != $this->Auth->user('org_id') || !$this->userRole['perm_modify'])) {
			throw new UnauthorizedException('You do not have permission to do that.');
		}
		if ($this->request->is('post')) {
			if ($this->__delete($id, $hard)) {
				$message = 'Object deleted.';
				if ($this->request->is('ajax')) {
					return new CakeResponse(
						array(
							'body'=> json_encode(
								array(
									'saved' => true,
									'success' => $message
								)
							),
							'status'=>200,
							'type' => 'json'
						)
					);
				} else if ($this->_isRest()) {
					return $this->RestResponse->saveSuccessResponse(
						'Objects',
						'delete',
						$id,
						$this->response->type()
					);
				} else {
					$this->Session->setFlash($message);
					$this->redirect(array('controller' => 'events', 'action' => 'view', $object['Event']['id']));
				}
			} else {
				$message = 'Object could not be deleted.';
				if ($this->request->is('ajax')) {
					return new CakeResponse(
						array(
							'body'=> json_encode(
								array(
									'saved' => false,
									'errors' => $message
								)
							),
							'status'=>200,
							'type' => 'json'
						)
					);
				} else if ($this->_isRest()) {
					return $this->RestResponse->saveFailResponse(
						'Objects',
						'delete',
						false,
						$this->MispObject->validationErrors,
						$this->response->type()
					);
				} else {
					$this->Session->setFlash($message);
					$this->redirect(array('controller' => 'events', 'action' => 'view', $object['Event']['id']));
				}
			}
		} else {
			if ($this->request->is('ajax') && $this->request->is('get')) {
				$this->set('hard', $hard);
				$this->set('id', $id);
				$this->set('event_id', $object['Event']['id']);
				$this->render('ajax/delete');
			}
		}
  }

	private function __delete($id, $hard) {
		$this->MispObject->id = $id;
		if (!$this->MispObject->exists()) {
			return false;
		}
		$object = $this->MispObject->find('first', array(
			'conditions' => array('Object.id' => $id),
			'fields' => array('Object.*'),
			'contain' => array(
				'Event' => array(
					'fields' => array('Event.*')
				),
				'Attribute' => array(
					'fields' => array('Attribute.*')
				)
			),
		));
		if (empty($object)) throw new MethodNotAllowedException('Object not found or not authorised.');

		// check for permissions
		if (!$this->_isSiteAdmin()) {
			if ($object['Event']['locked']) {
				if ($this->Auth->user('org_id') != $object['Event']['org_id'] || !$this->userRole['perm_sync']) {
					throw new MethodNotAllowedException('Object not found or not authorised.');
				}
			} else {
				if ($this->Auth->user('org_id') != $object['Event']['orgc_id']) {
					throw new MethodNotAllowedException('Object not found or not authorised.');
				}
			}
		}
		$date = new DateTime();
		if ($hard) {
			// For a hard delete, simply run the delete, it will cascade
			$this->MispObject->delete($id);
			return true;
		} else {
			// For soft deletes, sanitise the object first if the setting is enabled
			if (Configure::read('Security.sanitise_attribute_on_delete')) {
				$object['Object']['name'] = 'N/A';
				$object['Object']['category'] = 'N/A';
				$object['Object']['description'] = 'N/A';
				$object['Object']['template_uuid'] = 'N/A';
				$object['Object']['template_version'] = 0;
				$object['Object']['comment'] = '';
			}
			$object['Object']['deleted'] = 1;
			$object['Object']['timestamp'] = $date->getTimestamp();
			$this->MispObject->save($object);
			foreach ($object['Attribute'] as $attribute) {
				if (Configure::read('Security.sanitise_attribute_on_delete')) {
						$attribute['category'] = 'Other';
						$attribute['type'] = 'comment';
						$attribute['value'] = 'deleted';
						$attribute['comment'] = '';
						$attribute['to_ids'] = 0;
				}
				$attribute['deleted'] = 1;
				$attribute['timestamp'] = $date->getTimestamp();
				$this->MispObject->Attribute->save(array('Attribute' => $attribute));
				$this->MispObject->Event->ShadowAttribute->deleteAll(
					array('ShadowAttribute.old_id' => $attribute['id']),
					false
				);
			}
			$this->MispObject->Event->unpublishEvent($object['Event']['id']);
			$object_refs = $this->MispObject->ObjectReference->find('all', array(
				'conditions' => array(
					'ObjectReference.referenced_type' => 1,
					'ObjectReference.referenced_id' => $id,
				),
				'recursive' => -1
			));
			foreach ($object_refs as $ref) {
				$ref['ObjectReference']['deleted'] = 1;
				$this->MispObject->ObjectReference->save($ref);
			}
			return true;
		}
	}

  public function view($id) {
		if ($this->_isRest()) {
			$objects = $this->MispObject->fetchObjects($this->Auth->user(), array('conditions' => array('Object.id' => $id)));
			if (!empty($objects)) {
				return $this->RestResponse->viewData($objects, $this->response->type());
			}
		}
  }
}
