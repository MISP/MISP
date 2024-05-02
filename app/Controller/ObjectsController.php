<?php

App::uses('AppController', 'Controller');
App::uses('JsonTool', 'Tools');

/**
 * @property MispObject $MispObject
 */
class ObjectsController extends AppController
{
    public $uses = 'MispObject';

    public $components = array('RequestHandler', 'Session');

    public $paginate = array(
            'limit' => 20,
            'order' => array(
                    'Object.id' => 'desc'
            ),
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (!$this->_isRest()) {
            $this->Security->unlockedActions = array('revise_object', 'get_row');
        }
    }

    public function revise_object($action, $event_id, $template_id, $object_id = false, $update_template_available = false, $similar_objects_display_threshold=15)
    {
        if (!$this->request->is('post') && !$this->request->is('put')) {
            throw new MethodNotAllowedException(__('This action can only be reached via POST requests'));
        }
        $this->request->data = $this->MispObject->attributeCleanup($this->request->data);
        $template = $this->MispObject->ObjectTemplate->find('first', array(
            'conditions' => array('ObjectTemplate.id' => $template_id),
            'recursive' => -1,
            'contain' => array(
                'ObjectTemplateElement'
            )
        ));
        $event = $this->MispObject->Event->fetchSimpleEvent($this->Auth->user(), $event_id, ['contain' => ['Orgc']]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
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
            $sgs = $this->MispObject->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', false, array_keys($sharing_groups));
            $this->set('sharing_groups', $sgs);
        }

        if (isset($this->request->data['Attribute'])) {
            foreach ($this->request->data['Attribute'] as &$attribute) {
                if (empty($attribute['uuid'])) {
                    $attribute['uuid'] = CakeText::uuid();
                }
                $validation = $this->MispObject->Attribute->validateAttribute($attribute, false);
                if ($validation !== true) {
                    $attribute['validation'] = $validation;
                }
            }
        }

        $this->set('distributionLevels', $this->MispObject->Attribute->distributionLevels);
        $this->set('action', $action);
        $this->set('template', $template);
        $this->set('object_id', $object_id);
        $this->set('event', $event);
        $this->set('data', $this->request->data);
        $this->set('update_template_available', !empty($update_template_available));
        // Make sure the data stored in the session applies to this object. User might be prompted to perform a merge with another object if the session's data is somehow not cleaned
        $curObjectTmpUuid = CakeText::uuid();
        $this->set('cur_object_tmp_uuid', $curObjectTmpUuid);
        $this->Session->write('object_being_created', array(
            'cur_object_tmp_uuid' => $curObjectTmpUuid,
            'data' => $this->request->data
        ));

        if ($action === 'add') {
            list($similar_objects_count, $similar_objects, $simple_flattened_attribute, $simple_flattened_attribute_noval) = $this->MispObject->findSimilarObjects(
                $this->Auth->user(),
                $event_id,
                $this->request->data['Attribute'],
                $template,
                $similar_objects_display_threshold
            );
            if ($similar_objects_count) {
                $this->set('similar_objects_count', $similar_objects_count);
                $this->set('similar_objects', $similar_objects);
                $this->set('similar_objects_display_threshold', $similar_objects_display_threshold);
                $this->set('simple_flattened_attribute', $simple_flattened_attribute);
                $this->set('simple_flattened_attribute_noval', $simple_flattened_attribute_noval);

                $multiple_template_elements = Hash::extract($template['ObjectTemplateElement'],'{n}[multiple=true]');
                $multiple_attribute_allowed = array();
                foreach ($multiple_template_elements as $template_element) {
                    $relation_type = $template_element['object_relation'] . ':' . $template_element['type'];
                    $multiple_attribute_allowed[$relation_type] = true;
                }
                $this->set('multiple_attribute_allowed', $multiple_attribute_allowed);
            }
        }
    }

    /**
     * Create an object using a template
     * POSTing will take the input and validate it against the template
     * GETing will return the template
     */
    public function add($eventId, $templateId = false, $version = false)
    {
        if (!$this->userRole['perm_modify']) {
            throw new ForbiddenException(__('You don\'t have permissions to create objects.'));
        }

        if (!empty($templateId) && Validation::uuid($templateId)) {
            $conditions = array('ObjectTemplate.uuid' => $templateId);
            if (!empty($version)) {
                $conditions['ObjectTemplate.version'] = $version;
            }
            $temp = $this->MispObject->ObjectTemplate->find('all', array(
                'recursive' => -1,
                'fields' => array('ObjectTemplate.id', 'ObjectTemplate.uuid', 'ObjectTemplate.version'),
                'conditions' => $conditions
            ));
            if (!empty($temp)) {
                $version = 0;
                foreach ($temp as $tempTemplate) {
                    if ($tempTemplate['ObjectTemplate']['version'] > $version) {
                        $version = $tempTemplate['ObjectTemplate']['version'];
                        $templateId = $tempTemplate['ObjectTemplate']['id'];
                    }
                }
                unset($temp);
            } else {
                throw new NotFoundException(__('Invalid template.'));
            }
        }
        // Find the event that is to be updated
        $event = $this->MispObject->Event->fetchSimpleEvent($this->Auth->user(), $eventId, ['contain' => ['Orgc']]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        $eventId = $event['Event']['id'];
        if (!$this->_isRest()) {
            $this->MispObject->Event->insertLock($this->Auth->user(), $eventId);
        }
        $error = false;
        $template = false;
        if (!empty($templateId) || !$this->_isRest()) {
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
            if (empty($template)) {
                $error = 'No valid template found to edit the object.';
            }
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
            $breakOnDuplicate = !empty($this->request->data['Object']['breakOnDuplicate']) || !empty($this->params['named']['breakOnDuplicate']);
            $object = $this->MispObject->attributeCleanup($this->request->data);
            // we pre-validate the attributes before we create an object at this point
            // This allows us to stop the process and return an error (API) or return
            //  to the add form
            if (empty($object['Attribute'])) {
                $error = 'Could not save the object as no attributes were set.';
            } else {
                foreach ($object['Attribute'] as $k => $attribute) {
                    unset($object['Attribute'][$k]['id']);
                    $object['Attribute'][$k]['event_id'] = $eventId;
                    $this->MispObject->Event->Attribute->set($object['Attribute'][$k]);
                    if (!$this->MispObject->Event->Attribute->validates()) {
                        $validationErrors = $this->MispObject->Event->Attribute->validationErrors;
                        $isCompositeError = isset($validationErrors['value']) && $validationErrors['value'][0] === 'Composite type found but the value not in the composite (value1|value2) format.';
                        if (!$isCompositeError) {
                            $error = sprintf(
                                'Could not save object as at least one attribute has failed validation (%s). %s',
                                isset($attribute['object_relation']) ? $attribute['object_relation'] : 'No object_relation',
                                json_encode($validationErrors)
                            );
                        }
                    }
                }
            }
            if (empty($error)) {
                if (empty($template)) {
                    if (!empty($object['Object']['template_uuid']) && !empty($object['Object']['template_version'])) {
                        $template = $this->MispObject->ObjectTemplate->find('first', array(
                            'conditions' => array(
                                'ObjectTemplate.uuid' => $object['Object']['template_uuid'],
                                'ObjectTemplate.version' => $object['Object']['template_version']
                            ),
                            'recursive' => -1,
                            'contain' => array(
                                'ObjectTemplateElement'
                            )
                        ));
                    }
                }
                if (!empty($template)) {
                    $conformity = $this->MispObject->ObjectTemplate->checkTemplateConformity($template, $object);
                    if ($conformity !== true) {
                        $error = $conformity;
                    }
                }
                if (empty($error)) {
                    unset($object['Object']['id']);
                    $result = $this->MispObject->saveObject($object, $eventId, $template, $this->Auth->user(), 'halt', $breakOnDuplicate);
                    if (is_numeric($result)) {
                        $this->MispObject->Event->unpublishEvent($event);
                    } else {
                        $object_validation_errors = array();
                        foreach($result as $field => $field_errors) {
                            $object_validation_errors[] = sprintf('%s: %s', $field,  implode(', ', $field_errors));
                        }
                        $error = __('Object could not be saved.') . PHP_EOL . implode(PHP_EOL, $object_validation_errors);
                    }
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
                        if (!empty($object)) {
                            $object['Object']['Attribute'] = $object['Attribute'];
                            unset($object['Attribute']);
                        }
                        return $this->RestResponse->viewData($object, $this->response->type());
                    } else {
                        return $this->RestResponse->saveFailResponse('Objects', 'add', false, $error, $this->response->type());
                    }
                } else {
                    if (is_numeric($result)) {
                        $this->Flash->success('Object saved.');
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
                $this->Flash->error($error);
            }
            $template = $this->MispObject->prepareTemplate($template, $this->request->data);
            $enabledRows = array_keys($template['ObjectTemplateElement']);
            $this->set('enabledRows', $enabledRows);
            $distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($this->Auth->user());
            $this->set('distributionData', $distributionData);
            $this->set('event', $event);
            $this->set('action', 'add');
            $this->set('template', $template);
        }
    }

    public function get_row($template_id, $object_relation, $k)
    {
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
            if ($templateElement['object_relation'] === $object_relation) {
                $element = $templateElement;
                break;
            }
        }

        if (empty($element)) {
            throw new NotFoundException(__("Object template do not contains object relation $object_relation"));
        }

        $distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($this->Auth->user());
        $this->layout = false;
        $this->set('distributionData', $distributionData);
        $this->set('k', $k);
        $this->set('element', $element);
    }

    public function edit($id, $update_template_available=false, $onlyAddNewAttribute=false)
    {
        $user = $this->Auth->user();
        $object = $this->MispObject->fetchObjects($user, array(
            'conditions' => $this->__objectIdToConditions($id),
        ));
        if (empty($object)) {
            throw new NotFoundException(__('Invalid object.'));
        }
        $object = $object[0];
        $event = $this->MispObject->Event->fetchSimpleEvent($user, $object['Event']['id']);
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('Insufficient permissions to edit this object.'));
        }
        if (!$this->_isRest()) {
            $this->MispObject->Event->insertLock($user, $object['Event']['id']);
        }
        if (!empty($object['Object']['template_uuid']) && !empty($object['Object']['template_version'])) {
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
        }
        if (empty($template) && !$this->_isRest() && !$update_template_available) {
            $this->Flash->error('Object cannot be edited, no valid template found. ', ['params' => ['url' => sprintf('/objects/edit/%s/1/0', $id), 'urlName' => __('Force update anyway')]]);
            $this->redirect(array('controller' => 'events', 'action' => 'view', $object['Object']['event_id']));
        }
        if (!empty($template) || $update_template_available) {
            $templateData = $this->MispObject->resolveUpdatedTemplate($template, $object, $update_template_available);
            $this->set('updateable_attribute', $templateData['updateable_attribute']);
            $this->set('not_updateable_attribute', $templateData['not_updateable_attribute']);
            $this->set('original_template_unkown', $templateData['original_template_unkown']);
            if (!empty($this->Session->read('object_being_created')) && !empty($this->params['named']['cur_object_tmp_uuid'])) {
                $revisedObjectData = $this->Session->read('object_being_created');
                if ($this->params['named']['cur_object_tmp_uuid'] == $revisedObjectData['cur_object_tmp_uuid']) { // ensure that the passed session data is for the correct object
                    $revisedObjectData = $revisedObjectData['data'];
                } else {
                    $this->Session->delete('object_being_created');
                    $revisedObjectData = array();
                }
            }
            if (!empty($revisedObjectData)) {
                $revisedData = $this->MispObject->reviseObject($revisedObjectData, $object, $template);
                $this->set('revised_object', $revisedData['revised_object_both']);
                $object = $revisedData['object'];
            }
            if (!empty($templateData['template'])) {
                $template = $this->MispObject->prepareTemplate($templateData['template'], $object);
            }
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->Session->delete('object_being_created');
            if (isset($this->request->data['request'])) {
                $this->request->data = $this->request->data['request'];
            }
            if (empty($this->request->data['Object'])) {
              $this->request->data['Object'] = $this->request->data;
            }
            if (isset($this->request->data['Object']['data'])) {
                $this->request->data = JsonTool::decode($this->request->data['Object']['data']);
            }
            if (isset($this->request->data['Object'])) {
                $this->request->data = array_merge($this->request->data, $this->request->data['Object']);
                unset($this->request->data['Object']);
            }
            $objectToSave = $this->MispObject->attributeCleanup($this->request->data);
            $objectToSave = $this->MispObject->deltaMerge($object, $objectToSave, $onlyAddNewAttribute, $user);
            $error_message = __('Object could not be saved.');
            $savedObject = array();
            if (!is_numeric($objectToSave)) {
                $object_validation_errors = array();
                foreach ($objectToSave as $field => $field_errors) {
                    $object_validation_errors[] = sprintf('%s: %s', $field,  implode(', ', $field_errors));
                }
                $error_message = __('Object could not be saved.') . PHP_EOL . implode(PHP_EOL, $object_validation_errors);
            } else {
                $savedObject = $this->MispObject->fetchObjects($user, array('conditions' => array('Object.id' => $object['Object']['id'])));
                if (isset($this->request->data['deleted']) && $this->request->data['deleted']) {
                    $this->MispObject->deleteObject($savedObject[0], $hard=false, $unpublish=false);
                    $savedObject = $this->MispObject->fetchObjects($user, array('conditions' => array('Object.id' => $object['Object']['id']))); // make sure the object is deleted
                }
            }
            // we pre-validate the attributes before we create an object at this point
            // This allows us to stop the process and return an error (API) or return
            //  to the add form
            if ($this->_isRest()) {
                if (is_numeric($objectToSave)) {
                    if (!empty($savedObject)) {
                        $savedObject = $savedObject[0];
                        $savedObject['Object']['Attribute'] = $savedObject['Attribute'];
                        unset($savedObject['Attribute']);
                        $this->MispObject->Event->unpublishEvent($event);
                    }
                    return $this->RestResponse->viewData($savedObject, $this->response->type());
                } else {
                    return $this->RestResponse->saveFailResponse('Objects', 'edit', false, $id, $this->response->type());
                }
            } else {
                if ($this->request->is('ajax')) {
                    if (is_numeric($objectToSave)) {
                        $this->MispObject->Event->unpublishEvent($event);
                        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => __('Object attributes saved.'))), 'status'=>200, 'type' => 'json'));
                    } else {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => $error_message)), 'status'=>200, 'type' => 'json'));
                    }
                } else {
                    if (is_numeric($objectToSave)) {
                        $this->MispObject->Event->unpublishEvent($event);
                        $this->Flash->success('Object saved.');
                    } else {
                        $this->Flash->error($error_message);
                    }
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $object['Object']['event_id']));
                }
            }
        } else {
            $enabledRows = array();
            $this->request->data['Object'] = $object['Object'];
            foreach ($template['ObjectTemplateElement'] as $k => $element) {
                foreach ($object['Attribute'] as $attribute) {
                    if ($attribute['object_relation'] === $element['object_relation']) {
                        $enabledRows[] = $k;
                        $this->request->data['Attribute'][$k] = $attribute;
                        if (!empty($element['values_list'])) {
                            $this->request->data['Attribute'][$k]['value_select'] = $attribute['value'];
                        } else {
                            if (!empty($element['sane_default'])) {
                                if (in_array($attribute['value'], $element['sane_default'], true)) {
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
        $distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($user);
        $this->set('distributionData', $distributionData);
        $this->set('event', $event);
        $this->set('ajax', false);
        $this->set('template', $template);
        $this->set('action', 'edit');
        $this->set('object', $object);
        $this->set('update_template_available', $update_template_available);
        $this->set('newer_template_version', empty($templateData['newer_template_version']) ? false : $templateData['newer_template_version']);
        $this->render('add');
    }

    // ajax edit - post a single edited field and this method will attempt to save it and return a json with the validation errors if they occur.
    public function editField($id)
    {
        if ((!$this->request->is('post') && !$this->request->is('put'))) {
            throw new MethodNotAllowedException(__('This function can only be accessed via POST or PUT'));
        }
        $object = $this->MispObject->find('first', array(
            'conditions' => $this->__objectIdToConditions($id),
            'contain' => 'Event',
            'recursive' => -1
        ));
        if (empty($object)) {
            return $this->RestResponse->saveFailResponse('Objects', 'edit', false, 'Invalid object');
        }
        if (!$this->__canModifyEvent($object)) {
            return $this->RestResponse->saveFailResponse('Objects', 'edit', false, 'You do not have permission to do that.');
        }
        $validFields = array('comment', 'distribution', 'first_seen', 'last_seen');
        $changed = false;
        if (empty($this->request->data['Object'])) {
            $this->request->data = array('Object' => $this->request->data);
            if (empty($this->request->data['Object'])) {
                throw new MethodNotAllowedException('Invalid input.');
            }
        }
        $seen_changed = false;
        foreach ($this->request->data['Object'] as $changedKey => $changedField) {
            if (!in_array($changedKey, $validFields)) {
                throw new MethodNotAllowedException('Invalid field.');
            }
            if ($object['Object'][$changedKey] == $changedField) {
                $this->autoRender = false;
                return $this->RestResponse->saveSuccessResponse('Objects', 'edit', $id, false, 'nochange');
            }
            $seen_changed = $changedKey == 'first_seen' || $changedKey == 'last_seen';
            $object['Object'][$changedKey] = $changedField;
            $changed = true;
        }
        $forcedSeenOnElements = array();
        if (!$changed) {
            return $this->RestResponse->saveSuccessResponse('Objects', 'edit', $id, false, 'nochange');
        } elseif ($seen_changed) {
            $forcedSeenOnElements[$changedKey] = $changedField;
        }
        $date = new DateTime();
        $object['Object']['timestamp'] = $date->getTimestamp();
        $object = $this->MispObject->syncObjectAndAttributeSeen($object, $forcedSeenOnElements, false);
        if ($this->MispObject->save($object)) {
            $this->MispObject->Event->unpublishEvent($object, false, $date->getTimestamp());
            if ($seen_changed) {
                $this->MispObject->Attribute->saveAttributes($object['Attribute'], $this->Auth->user());
            }
            return $this->RestResponse->saveSuccessResponse('Objects', 'edit', $id, false, 'Field updated');
        } else {
            return $this->RestResponse->saveFailResponse('Objects', 'edit', false, $this->MispObject->validationErrors);
        }
    }

    public function fetchViewValue($id, $field = null)
    {
        $validFields = array('timestamp', 'comment', 'distribution', 'first_seen', 'last_seen');
        if (!isset($field) || !in_array($field, $validFields, true)) {
            throw new MethodNotAllowedException('Invalid field requested.');
        }
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be accessed via AJAX.');
        }
        $params = array(
            'conditions' => array('Object.id' => $id),
            'fields' => array('id', 'distribution', 'event_id', $field),
            'contain' => array(
                'Event' => array(
                    'fields' => array('distribution', 'id', 'org_id'),
                )
            ),
            'flatten' => 1
        );
        $object = $this->MispObject->fetchObjectSimple($this->Auth->user(), $params);
        if (empty($object)) {
            throw new NotFoundException(__('Invalid object'));
        }
        $object = $object[0];
        $result = $object['Object'][$field];
        if ($field === 'distribution') {
            $this->set('shortDist', $this->MispObject->Attribute->shortDist);
        }
        $this->set('value', $result);
        $this->set('field', $field);
        $this->layout = false;
        $this->render('ajax/objectViewFieldForm');
    }

    public function fetchEditForm($id, $field = null)
    {
        $validFields = array('distribution', 'comment', 'first_seen', 'last_seen');
        if (!isset($field) || !in_array($field, $validFields)) {
            throw new MethodNotAllowedException('Invalid field requested.');
        }
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be accessed via AJAX.');
        }
        $fields = array('id', 'distribution', 'event_id');
        $fields[] = $field;
        $params = array(
            'conditions' => array('Object.id' => $id),
            'fields' => $fields,
            'contain' => array(
                'Event' => array(
                    'fields' => array('distribution', 'id', 'user_id', 'orgc_id', 'org_id'),
                )
            )
        );
        $object = $this->MispObject->fetchObjectSimple($this->Auth->user(), $params);
        if (empty($object)) {
            throw new NotFoundException(__('Invalid attribute'));
        }
        $object = $object[0];
        if (!$this->__canModifyEvent($object)) {
            throw new NotFoundException(__('Invalid object'));
        }
        $this->layout = false;
        if ($field === 'distribution') {
            $distributionLevels = $this->MispObject->shortDist;
            unset($distributionLevels[4]);
            $this->set('distributionLevels', $distributionLevels);
        }
        $this->set('object', $object['Object']);
        $fieldURL = ucfirst($field);
        $this->render('ajax/objectEdit' . $fieldURL . 'Form');
    }

    // Construct a template with valid object attributes to add to an object
    public function quickFetchTemplateWithValidObjectAttributes($id)
    {
        $params = array(
            'conditions' => array('Object.id' => $id),
            'fields' => array('template_uuid', 'template_version', 'id'),
            'flatten' => 1,
        );
        // fetchObjects restrict access based on user
        $object = $this->MispObject->fetchObjects($this->Auth->user(), $params);
        if (empty($object)) {
            if ($this->request->is('ajax')) {
                return $this->RestResponse->saveFailResponse('Objects', 'add', false, 'Invalid object', $this->response->type());
            } else {
                throw new NotFoundException(__('Invalid object'));
            }
        } else {
            $object = $object[0];
        }
        // get object attributes already set
        $existsObjectRelation = array();
        foreach ($object['Attribute'] as $attr) {
            $existsObjectRelation[$attr['object_relation']] = true;
        }
        // get object attribute defined in the object's template
        $template = $this->MispObject->ObjectTemplate->find('first', array(
            'conditions' => array(
                'ObjectTemplate.uuid' => $object['Object']['template_uuid'],
                'ObjectTemplate.version' => $object['Object']['template_version'],
            ),
            'recursive' => -1,
            'flatten' => 1,
            'contain' => 'ObjectTemplateElement'
        ));
        if (empty($template)) {
            if ($this->request->is('ajax')) {
                return $this->RestResponse->saveFailResponse('Objects', 'add', false, 'Invalid template', $this->response->type());
            } else {
                throw new NotFoundException(__('Invalid template'));
            }
        }
        // unset object invalid object attribute
        foreach ($template['ObjectTemplateElement'] as $i => $objAttr) {
            if (isset($existsObjectRelation[$objAttr['object_relation']]) && !$objAttr['multiple']) {
                unset($template['ObjectTemplateElement'][$i]);
            }
        }
        if ($this->request->is('get') || $this->request->is('post')) {
            $this->set('template', $template);
            $this->set('objectId', $object['Object']['id']);

            $items = array();
            foreach ($template['ObjectTemplateElement'] as $objectAttribute) {
                $name = sprintf('%s :: %s', $objectAttribute['object_relation'], $objectAttribute['type']);
                $items[] = array(
                    'name' => $name,
                    'value' => '/objects/quickAddAttributeForm/' . $object['Object']['id'] . '/' . $objectAttribute['object_relation'],
                    'template' => array(
                        'name' => $name,
                        'infoExtra' => $objectAttribute['description'],
                    )
                );
            }
            $this->set('options', array(
                'flag_redraw_chosen' => true
            ));
            $this->set('items', $items);
            $this->render('/Elements/generic_picker');
        } else {
            return $template;
        }
    }

    /**
     * GET: Returns a form allowing to add a valid object attribute to an object
     * POST/PUT: Add the attribute to the object
     */
    public function quickAddAttributeForm($id, $fieldName = null)
    {
        if ($this->request->is('GET')) {
            if (!isset($fieldName)) {
                throw new MethodNotAllowedException('No field requested.');
            }
            $params = array(
                'conditions' => array('Object.id' => $id),
                'fields' => array('template_uuid', 'template_version', 'id', 'event_id'),
                'flatten' => 1,
                'contain' => array(
                    'Event' => ['fields' => ['id', 'user_id', 'org_id', 'orgc_id']]
                )
            );
            // fetchObjects restrict access based on user
            $object = $this->MispObject->fetchObjects($this->Auth->user(), $params);
            if (empty($object)) {
                throw new NotFoundException(__('Invalid object'));
            }
            $object = $object[0];
            if (!$this->__canModifyEvent($object)) {
                throw new ForbiddenException(__('You do not have permission to do that.'));
            }
            $template = $this->MispObject->ObjectTemplate->find('first', array(
                'conditions' => array(
                    'ObjectTemplate.uuid' => $object['Object']['template_uuid'],
                    'ObjectTemplate.version' => $object['Object']['template_version'],
                ),
                'recursive' => -1,
                'flatten' => 1,
                'contain' => array(
                    'ObjectTemplateElement' => array('conditions' => array(
                        'object_relation' => $fieldName
                    ))
                )
            ));
            if (empty($template)) {
                throw new NotFoundException(__('Invalid template'));
            }
            if (empty($template['ObjectTemplateElement'])) {
                throw new NotFoundException(__('Invalid field `%s`', h($fieldName)));
            }

            // check if fields can be added
            foreach ($object['Attribute'] as $objAttr) {
                $objectAttrFromTemplate = $template['ObjectTemplateElement'][0];
                if ($objAttr['object_relation'] === $fieldName && !$objectAttrFromTemplate['multiple']) {
                    throw new NotFoundException(__('Invalid field'));
                }
            }
            $template = $this->MispObject->prepareTemplate($template, $object);
            $this->layout = false;
            $this->set('object', $object['Object']);
            $template_element = $template['ObjectTemplateElement'][0];
            unset($template_element['value']); // avoid filling if multiple
            $this->set('template_element', $template_element);
            $distributionData = $this->MispObject->Attribute->fetchDistributionData($this->Auth->user());
            $this->set('distributionData', $distributionData);

            $info = ['category' => [], 'distribution' => []];
            foreach ($this->MispObject->Attribute->categoryDefinitions as $key => $value) {
                $info['category'][$key] = isset($value['formdesc']) ? $value['formdesc'] : $value['desc'];
            }
            foreach ($this->MispObject->Attribute->distributionLevels as $key => $value) {
                $info['distribution'][$key] = $this->MispObject->Attribute->distributionDescriptions[$key]['formdesc'];
            }

            $this->set('fieldDesc', $info);
            $this->render('ajax/quickAddAttributeForm');
        } else if ($this->request->is('post') || $this->request->is('put')) {
            return $this->edit($this->request->data['Object']['id'], false, true);
        }
    }

    public function delete($id, $hard = false)
    {
        if (!$this->userRole['perm_modify']) {
            throw new ForbiddenException(__('You don\'t have permissions to delete objects.'));
        }
        $object = $this->MispObject->find('first', array(
            'recursive' => -1,
            'fields' => array('Object.id', 'Object.event_id', 'Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.user_id'),
            'conditions' => $this->__objectIdToConditions($id),
            'contain' => array(
                'Event'
            )
        ));
        if (empty($object)) {
            throw new NotFoundException(__('Invalid object.'));
        }
        if (!$this->__canModifyEvent($object)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        $eventId = $object['Event']['id'];
        if (!$this->_isRest()) {
            $this->MispObject->Event->insertLock($this->Auth->user(), $eventId);
        }
        if ($this->request->is('post') || $this->request->is('delete')) {
            if (!empty($this->request->data['hard'])) {
                $hard = true;
            }
            if ($this->__delete($object['Object']['id'], $hard)) {
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
                } elseif ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse(
                        'Objects',
                        'delete',
                        $eventId,
                        $this->response->type()
                    );
                } else {
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
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
                } elseif ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse(
                        'Objects',
                        'delete',
                        false,
                        $this->MispObject->validationErrors,
                        $this->response->type()
                    );
                } else {
                    $this->Flash->error($message);
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $object['Event']['id']));
                }
            }
        } else {
            if ($this->request->is('ajax') && $this->request->is('get')) {
                $this->set('hard', $hard);
                $this->set('id', $id);
                $this->set('event_id', $eventId);
                $this->render('ajax/delete');
            }
        }
    }

    private function __delete($id, $hard)
    {
        $options = array(
            'conditions' => array('Object.id' => $id)
        );
        $object = $this->MispObject->fetchObjects($this->Auth->user(), $options);
        if (empty($object)) {
            throw new MethodNotAllowedException(__('Object not found or not authorised.'));
        }
        $object = $object[0];
        return $this->MispObject->deleteObject($object, $hard=$hard);
    }

    public function view($id)
    {
        if ($this->request->is('head')) { // Just check if object exists
            $exists = $this->MispObject->fetchObjects($this->Auth->user(), [
                'conditions' => $this->__objectIdToConditions($id),
                'metadata' => true,
            ]);
            return new CakeResponse(['status' => $exists ? 200 : 404]);
        }

        $objects = $this->MispObject->fetchObjects($this->Auth->user(), array(
            'conditions' => $this->__objectIdToConditions($id),
        ));
        if (empty($objects)) {
            throw new NotFoundException(__('Invalid object.'));
        }
        $object = $objects[0];
        if ($this->_isRest()) {
            if (!empty($object['Event'])) {
                $object['Object']['Event'] = $object['Event'];
            }
            if (!empty($object['Attribute'])) {
                $object['Object']['Attribute'] = $object['Attribute'];
            }
            return $this->RestResponse->viewData(array('Object' => $object['Object']), $this->response->type());
        } else {
            $this->redirect('/events/view/' . $object['Object']['event_id']);
        }
    }

    public function orphanedObjectDiagnostics()
    {
        $objectIds = $this->MispObject->find('list', array(
            'fields' => array('id', 'event_id')
        ));
        $template_uuids = $this->MispObject->ObjectTemplate->find('list', array(
            'recursive' => -1,
            'fields' => array('ObjectTemplate.version', 'ObjectTemplate.id', 'ObjectTemplate.uuid')
        ));
        $template_ids = array();
        foreach ($template_uuids as $template_uuid) {
            $template_ids[] = end($template_uuid);
        }
        $templates = $this->MispObject->ObjectTemplate->find('all', array(
            'conditions' => array('ObjectTemplate.id' => $template_ids),
            'recursive' => -1,
            'fields' => array(
                'ObjectTemplate.id',
                'ObjectTemplate.uuid',
                'ObjectTemplate.name',
                'ObjectTemplate.version',
                'ObjectTemplate.description',
                'ObjectTemplate.meta-category',
            ),
            'contain' => array('ObjectTemplateElement' => array('fields' => array('ObjectTemplateElement.object_relation', 'ObjectTemplateElement.type')))
        ));
        foreach ($templates as $k => $v) {
            $templates[$k]['elements'] = array();
            foreach ($v['ObjectTemplateElement'] as $k2 => $v2) {
                $templates[$k]['elements'][$v2['object_relation']] = $v2['type'];
            }
            unset($templates[$k]['ObjectTemplateElement']);
        }
        $count = 0;
        $capturedObjects = array();
        $unmappedAttributes = array();
        foreach ($objectIds as $objectId => $event_id) {
            $attributes = $this->MispObject->Attribute->find('all', array(
                'conditions' => array(
                    'Attribute.object_id' => $objectId,
                    'Attribute.event_id !=' => $event_id,
                    'Attribute.deleted' => 0
                ),
                'recursive' => -1
            ));
            $matched_template = false;
            if (!empty($attributes)) {
                foreach ($templates as $template) {
                    $fail = false;
                    $original_event_id = false;
                    $original_timestamp = false;
                    foreach ($attributes as $ka => $attribute) {
                        if ($original_event_id == false) {
                            $original_event_id = $attribute['Attribute']['event_id'];
                        }
                        if ($original_timestamp == false) {
                            $original_timestamp = $attribute['Attribute']['timestamp'] -1;
                        } elseif ($original_event_id != $attribute['Attribute']['event_id']) {
                            unset($attributes[$ka]);
                            break;
                        }
                        if (!isset($template['elements'][$attribute['Attribute']['object_relation']]) || $template['elements'][$attribute['Attribute']['object_relation']] != $attribute['Attribute']['type']) {
                            $fail = true;
                            break;
                        }
                    }
                    $template['ObjectTemplate']['timestamp'] = $original_timestamp;
                    if (!$fail) {
                        $matched_template = $template;
                        $template['ObjectTemplate']['template_uuid'] = $template['ObjectTemplate']['uuid'];
                        unset($template['ObjectTemplate']['uuid']);
                        $template['ObjectTemplate']['template_version'] = $template['ObjectTemplate']['version'];
                        unset($template['ObjectTemplate']['version']);
                        $template['ObjectTemplate']['original_id'] = $objectId;
                        unset($template['ObjectTemplate']['id']);
                        $template['ObjectTemplate']['distribution'] = 0;
                        $template['ObjectTemplate']['sharing_group_id'] = 0;
                        $template['ObjectTemplate']['comment'] = '';
                        $template['ObjectTemplate']['event_id'] = $original_event_id;
                        $capturedObjects[$objectId]['Object'] = $template['ObjectTemplate'];
                        $capturedObjects[$objectId]['Attribute'] = array();
                        foreach ($attributes as $attribute) {
                            if ($attribute['Attribute']['event_id'] == $original_event_id) {
                                $capturedObjects[$objectId]['Attribute'][] = $attribute['Attribute'];
                            } else {
                                $unmappedAttributes[] = $attribute['Attribute'];
                            }
                        }
                        $this->loadModel('Log');
                        $logEntries = $this->Log->find('list', array(
                            'recursive' => -1,
                            'conditions' => array(
                                'model_id' => $template['ObjectTemplate']['original_id'],
                                'action' => 'add',
                                'model' => 'MispObject'
                            ),
                            'fields' => array('id', 'change'),
                            'sort' => array('id asc')
                        ));
                        $capturedOriginalData = array();
                        // reconstructing object details via log entries
                        if (!empty($logEntries)) {
                            $logEntry = reset($logEntries);
                            preg_match('/event_id.\(\).\=\>.\(([0-9]+)?\)/', $logEntry, $capturedOriginalData['event_id']);
                            preg_match('/uuid.\(\).\=\>.\(([0-9a-f\-]+)?\)/', $logEntry, $capturedOriginalData['uuid']);
                            preg_match('/distribution.\(\).\=\>.\(([0-9]+)?\)/', $logEntry, $capturedOriginalData['distribution']);
                            preg_match('/sharing_group_id.\(\).\=\>.\(([0-9]+)?\)/', $logEntry, $capturedOriginalData['sharing_group_id']);
                            if (!empty($capturedOriginalData['event_id']) && $capturedOriginalData['event_id'] == $original_event_id) {
                                if (isset($capturedOriginalData['uuid'][1])) {
                                    $capturedObjects[$objectId]['uuid'] = $capturedOriginalData['uuid'][1];
                                }
                                if (isset($capturedOriginalData['distribution'][1])) {
                                    $capturedObjects[$objectId]['distribution'] = $capturedOriginalData['distribution'][1];
                                }
                                if (isset($capturedOriginalData['sharing_group_id'][1])) {
                                    $capturedObjects[$objectId]['sharing_group_id'] = $capturedOriginalData['sharing_group_id'][1];
                                }
                            } else {
                                $capturedOriginalData = array();
                            }
                        }
                        $objectReferences = $this->MispObject->ObjectReference->find('all', array(
                            'recursive' => -1,
                            'conditions' => array(
                                'ObjectReference.event_id' => $original_event_id,
                                'ObjectReference.object_id' => $template['ObjectTemplate']['original_id']
                            )
                        ));
                        $objectReferencesReverse = $this->MispObject->ObjectReference->find('all', array(
                            'recursive' => -1,
                            'conditions' => array(
                                'ObjectReference.event_id' => $original_event_id,
                                'ObjectReference.referenced_id' => $template['ObjectTemplate']['original_id'],
                                'ObjectReference.referenced_type' => 1,
                            )
                        ));
                        $original_uuid = false;
                        if (!empty($objectReferences)) {
                            foreach ($objectReferences as $objectReference) {
                                $original_uuid = $objectReference['ObjectReference']['object_uuid'];
                                $capturedObjects[$objectId]['ObjectReference'][] = $objectReference['ObjectReference'];
                            }
                        }
                        if (!empty($objectReferencesReverse)) {
                            foreach ($objectReferencesReverse as $objectReference) {
                                $original_uuid = $objectReference['ObjectReference']['object_uuid'];
                                $capturedObjects[$objectId]['ObjectReferenceReverse'][] = $objectReference['ObjectReference'];
                            }
                        }
                        break;
                    }
                }
            }
        }
        if ($this->request->is('post')) {
            $success = 0;
            $log = ClassRegistry::init('Log');
            $queries = array();
            $counterQueries = array();
            foreach ($capturedObjects as $object) {
                $this->MispObject->create();
                $result = $this->MispObject->save($object);
                $id = intval($this->MispObject->id);
                if ($id > 0) {
                    $success++;
                    $saveResult['success']['Object'][] = $id;
                    foreach ($object['Attribute'] as $attribute) {
                        if (!empty($attribute['id']) && $attribute['id'] > 0) {
                            $queries[] = 'UPDATE attributes SET object_id = ' . $id . ' WHERE id = ' . intval($attribute['id']) . ';';
                            $counterQueries[] = 'UPDATE attributes SET object_id = ' . intval($attribute['object_id']) . ' WHERE id = ' . intval($attribute['id']) . ';';
                        }
                    }
                    if (!empty($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $reference) {
                            if (!empty($reference['id']) && $reference['id'] > 0) {
                                $queries[] = 'UPDATE object_references SET object_id = ' . $id . ' WHERE id = ' . intval($reference['id']) . ';';
                                $counterQueries[] = 'UPDATE object_references SET object_id = ' . intval($reference['object_id']) . ' WHERE id = ' . intval($reference['id']) . ';';
                            }
                        }
                    }
                    if (!empty($object['ObjectReferenceReverse'])) {
                        foreach ($object['ObjectReferenceReverse'] as $reference) {
                            if (!empty($reference['id']) && $reference['id'] > 0) {
                                $queries[] = 'UPDATE object_references SET referenced_id = ' . $id . ' WHERE id = ' . intval($reference['id']) . ';';
                                $counterQueries[] = 'UPDATE object_references SET referenced_id = ' . intval($reference['referenced_id']) . ' WHERE id = ' . intval($reference['id']) . ';';
                            }
                        }
                    }
                }
            }
            file_put_contents(APP . 'files/scripts/tmp/object_recovery_' . time() . '.sql', implode("\n", $counterQueries));
            $this->MispObject->query(implode("\n", $queries));
            $message = '';
            $this->Flash->success(__('%s objects successfully reconstructed.', $success));
            $this->redirect('/objects/orphanedObjectDiagnostics');
        }
        $this->set('captured', $capturedObjects);
        $this->set('unmapped', $unmappedAttributes);
    }

    public function proposeObjectsFromAttributes($eventId, $selectedAttributes='[]')
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This action can only be reached via AJAX.'));
        }

        $selectedAttributes = $this->_jsonDecode($selectedAttributes);
        $res = $this->MispObject->validObjectsFromAttributeTypes($this->Auth->user(), $eventId, $selectedAttributes);
        $this->set('potential_templates', $res['templates']);
        $this->set('selected_types', $res['types']);
        $this->set('event_id', $eventId);
    }

    public function groupAttributesIntoObject($event_id, $selected_template, $selected_attribute_ids='[]')
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This action can only be reached via AJAX.'));
        }

        $event = $this->MispObject->Event->find('first', array(
            'recursive' => -1,
            'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.user_id', 'Event.publish_timestamp'),
            'conditions' => array('Event.id' => $event_id)
        ));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        $hard_delete_attribute = $event['Event']['publish_timestamp'] == 0;
        if ($this->request->is('post')) {
            $template = $this->MispObject->ObjectTemplate->find('first', array(
                'recursive' => -1,
                'conditions' => array('ObjectTemplate.id' => $selected_template, 'ObjectTemplate.active' => true)
            ));
            if (empty($template)) {
                throw new NotFoundException(__('Invalid template.'));
            }
            $distribution = $this->request->data['Object']['distribution'];
            $sharingGroupId = $this->request->data['Object']['sharing_group_id'] ?? 0;
            $comment = $this->request->data['Object']['comment'];
            $selected_attribute_ids = $this->_jsonDecode($this->request->data['Object']['selectedAttributeIds']);
            $selected_object_relation_mapping = $this->_jsonDecode($this->request->data['Object']['selectedObjectRelationMapping']);
            if ($distribution == 4) {
                $sg = $this->MispObject->SharingGroup->fetchSG($sharingGroupId, $this->Auth->user());
                if (empty($sg)) {
                    throw new NotFoundException(__('Invalid sharing group.'));
                }
            } else {
                $sharingGroupId = 0;
            }
            $object = array(
                'Object' => array(
                    'distribution' => $distribution,
                    'sharing_group_id' => $sharingGroupId,
                    'comment' => $comment,
                ),
                'Attribute' => array()
            );
            $result = $this->MispObject->groupAttributesIntoObject($this->Auth->user(), $event_id, $object, $template, $selected_attribute_ids, $selected_object_relation_mapping, $hard_delete_attribute);
            if (is_numeric($result)) {
                $this->MispObject->Event->unpublishEvent($event);
                return $this->RestResponse->saveSuccessResponse('Objects', 'Created from Attributes', $result, $this->response->type());
            } else {
                $error = __('Failed to create an Object from Attributes. Error: ') . PHP_EOL . h($result);
                return $this->RestResponse->saveFailResponse('Objects', 'Created from Attributes', false, $error, $this->response->type());
            }
        } else {
            $selected_attribute_ids = $this->_jsonDecode($selected_attribute_ids);
            $selected_attributes = $this->MispObject->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array(
                'Attribute.id' => $selected_attribute_ids,
                'Attribute.event_id' => $event_id,
                'Attribute.object_id' => 0
            )));
            if (empty($selected_attributes)) {
                throw new MethodNotAllowedException(__('No Attribute selected.'));
            }
            $template = $this->MispObject->ObjectTemplate->find('first', array(
                'recursive' => -1,
                'conditions' => array('ObjectTemplate.id' => $selected_template, 'ObjectTemplate.active' => true),
                'contain' => 'ObjectTemplateElement'
            ));
            if (empty($template)) {
                throw new NotFoundException(__('Invalid template.'));
            }
            $attributeTypes = array_column(array_column($selected_attributes, 'Attribute'), 'type');
            $conformity_result = $this->MispObject->ObjectTemplate->checkTemplateConformityBasedOnTypes($template, $attributeTypes);
            $skipped_attributes = 0;
            foreach ($selected_attributes as $i => $attribute) {
                if (in_array($attribute['Attribute']['type'], $conformity_result['invalidTypes'], true)) {
                    unset($selected_attributes[$i]);
                    $array_position = array_search($attribute['Attribute']['id'], $selected_attribute_ids);
                    unset($selected_attribute_ids[$array_position]);
                    $skipped_attributes++;
                }
            }
            $object_relations = array();
            foreach ($template['ObjectTemplateElement'] as $template_element) {
                $object_relations[$template_element['type']][] = $template_element;
            }

            $object_references = $this->MispObject->ObjectReference->find('all', array(
                'conditions' => array(
                    'ObjectReference.referenced_id' => $selected_attribute_ids,
                ),
                'recursive' => -1
            ));

            foreach ($object_references as $i => $object_reference) {
                $temp_object = $this->MispObject->find('first', [
                    'conditions' => [
                        'id' => $object_reference['ObjectReference']['object_id']
                    ],
                    'recursive' => -1
                ]);
                $temp_attribute = $this->MispObject->Attribute->find('first', [
                    'conditions' => [
                        'id' => $object_reference['ObjectReference']['referenced_id'],
                    ],
                    'recursive' => -1
                ]);
                if (!empty($temp_object) && !empty($temp_attribute)) {
                    $temp_object = $temp_object['Object'];
                    $temp_attribute = $temp_attribute['Attribute'];
                    $object_references[$i]['ObjectReference']['object_name'] = $temp_object['name'];
                    $object_references[$i]['ObjectReference']['attribute_name'] = sprintf('%s/%s: "%s"', $temp_attribute['category'], $temp_attribute['type'], $temp_attribute['value']);
                }
            }

            $distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($this->Auth->user());
            $this->set('event_id', $event_id);
            $this->set('hard_delete_attribute', $hard_delete_attribute);
            $this->set('distributionData', $distributionData);
            $this->set('distributionLevels', $this->MispObject->Attribute->distributionLevels);
            $this->set('selectedTemplateTd', $selected_template);
            $this->set('selectedAttributeIds', $selected_attribute_ids);
            $this->set('template', $template);
            $this->set('object_relations', $object_relations);
            $this->set('attributes', $selected_attributes);
            $this->set('skipped_attributes', $skipped_attributes);
            $this->set('object_references', $object_references);
        }
    }

    public function createFromFreetext($eventId)
    {
        $this->request->allowMethod(['post']);

        $event = $this->MispObject->Event->find('first', array(
            'recursive' => -1,
            'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.user_id', 'Event.publish_timestamp'),
            'conditions' => array('Event.id' => $eventId)
        ));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }

        $requestData = $this->request->data['Object'];
        $selectedTemplateId = $requestData['selectedTemplateId'];
        $template = $this->MispObject->ObjectTemplate->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'ObjectTemplate.id' => $selectedTemplateId,
                'ObjectTemplate.active' => true,
            ),
            'contain' => ['ObjectTemplateElement'],
        ));
        if (empty($template)) {
            throw new NotFoundException(__('Invalid template.'));
        }

        if (isset($requestData['selectedObjectRelationMapping'])) {
            $distribution = $requestData['distribution'];
            $sharingGroupId = $requestData['sharing_group_id'] ?? 0;
            $comment = $requestData['comment'];
            if ($distribution == 4) {
                $sg = $this->MispObject->SharingGroup->fetchSG($sharingGroupId, $this->Auth->user());
                if (empty($sg)) {
                    throw new NotFoundException(__('Invalid sharing group.'));
                }
            } else {
                $sharingGroupId = 0;
            }

            $attributes = $this->_jsonDecode($requestData['attributes']);
            $selectedObjectRelationMapping = $this->_jsonDecode($requestData['selectedObjectRelationMapping']);

            // Attach object relation to attributes and fix tag format
            foreach ($attributes as $k => &$attribute) {
                $attribute['object_relation'] = $selectedObjectRelationMapping[$k];
                if (!empty($attribute['tags'])) {
                    $attribute['Tag'] = [];
                    foreach (explode(",", $attribute['tags']) as $tagName) {
                        $attribute['Tag'][] = [
                            'name' => trim($tagName),
                        ];
                    }
                    unset($attribute['tags']);
                }
            }

            $object = [
               'Object' => [
                   'event_id' => $eventId,
                   'distribution' => $distribution,
                   'sharing_group_id' => $sharingGroupId,
                   'comment' => $comment,
                   'Attribute' => $attributes,
               ],
            ];

            $object = $this->MispObject->fillObjectDataFromTemplate($object, $template);
            $result = $this->MispObject->captureObject($object, $eventId, $this->Auth->user(), true, false, $event);
            if ($result === true) {
                return $this->RestResponse->saveSuccessResponse('Objects', 'Created from Attributes', $result, 'json');
            } else {
                $error = __('Failed to create an Object from Attributes. Error: ') . PHP_EOL . h($result);
                return $this->RestResponse->saveFailResponse('Objects', 'Created from Attributes', false, $error, 'json');
            }
        } else {
            $attributes = $this->_jsonDecode($requestData['attributes']);

            $processedAttributes = [];
            foreach ($attributes as $attribute) {
                if ($attribute['type'] === 'ip-src/ip-dst') {
                    $types = array('ip-src', 'ip-dst');
                } elseif ($attribute['type'] === 'ip-src|port/ip-dst|port') {
                    $types = array('ip-src|port', 'ip-dst|port');
                } else {
                    $types = [$attribute['type']];
                }
                foreach ($types as $type) {
                    $attribute['type'] = $type;
                    $processedAttributes[] = $attribute;
                }
            }

            $attributeTypes = array_column($processedAttributes, 'type');
            $conformityResult = $this->MispObject->ObjectTemplate->checkTemplateConformityBasedOnTypes($template, $attributeTypes);

            if ($conformityResult['valid'] !== true || !empty($conformityResult['invalidTypes'])) {
                throw new NotFoundException(__('Invalid template.'));
            }

            $objectRelations = [];
            foreach ($template['ObjectTemplateElement'] as $templateElement) {
                $objectRelations[$templateElement['type']][] = $templateElement;
            }

            // Attach first object_relation according to attribute type that will be considered as default
            foreach ($processedAttributes as &$attribute) {
                $attribute['object_relation'] = $objectRelations[$attribute['type']][0]['object_relation'];
            }

            $distributionData = $this->MispObject->Event->Attribute->fetchDistributionData($this->Auth->user());
            $this->set('event', $event);
            $this->set('distributionData', $distributionData);
            $this->set('distributionLevels', $this->MispObject->Attribute->distributionLevels);
            $this->set('template', $template);
            $this->set('objectRelations', $objectRelations);
            $this->set('attributes', $processedAttributes);

            list($similar_objects_count, $similar_objects, $simple_flattened_attribute, $simple_flattened_attribute_noval) = $this->MispObject->findSimilarObjects(
                $this->Auth->user(),
                $eventId,
                $processedAttributes,
                $template
            );
            if ($similar_objects_count) {
                $this->set('similar_objects_count', $similar_objects_count);
                $this->set('similar_objects', $similar_objects);
                $this->set('similar_objects_display_threshold', 15);
                $this->set('simple_flattened_attribute', $simple_flattened_attribute);
                $this->set('simple_flattened_attribute_noval', $simple_flattened_attribute_noval);

                $multiple_template_elements = Hash::extract($template['ObjectTemplateElement'],'{n}[multiple=true]');
                $multiple_attribute_allowed = array();
                foreach ($multiple_template_elements as $template_element) {
                    $relation_type = $template_element['object_relation'] . ':' . $template_element['type'];
                    $multiple_attribute_allowed[$relation_type] = true;
                }
                $this->set('multiple_attribute_allowed', $multiple_attribute_allowed);
            }
        }
    }

    private function __objectIdToConditions($id)
    {
        if (is_numeric($id)) {
            $conditions = array('Object.id' => $id);
        } elseif (Validation::uuid($id)) {
            $conditions = array('Object.uuid' => $id);
        } else {
            throw new NotFoundException(__('Invalid object ID.'));
        }
        return $conditions;
    }

    public function viewAnalystData($id, $seed = null)
    {
        $this->MispObject->includeAnalystDataRecursive = true;
        $object = $this->MispObject->fetchObjects(
            $this->Auth->user(),
            [
                'conditions' => $this->__objectIdToConditions($id)
            ]
        );
        if(empty($object)) {
            throw new NotFoundException(__('Invalid Object.'));
        } else {
            $object[0]['Object'] = array_merge_recursive($object[0]['Object'], $this->MispObject->attachAnalystData($object[0]['Object']));
        }
        if ($this->_isRest()) {
            $validFields = ['Note', 'Opinion', 'Relationship'];
            $results = [];
            foreach ($validFields as $field) {
                if (!empty($object[0]['Object'][$field])) {
                    $results[$field] = $object[0]['Object'][$field];
                }
            }
            return $this->RestResponse->viewData($results, $this->response->type());
        }
        $this->layout = null;
        $this->set('shortDist', $this->MispObject->Attribute->shortDist);
        $this->set('object', $object[0]['Object']);
        $this->set('seed', $seed);
    }
}
