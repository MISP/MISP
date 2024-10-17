<?php

App::uses('AppController', 'Controller');

class DecayingModelController extends AppController
{
    public $components = array('RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                'DecayingModel.ID' => 'desc'
            )
    );

    public function update($force=false)
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->DecayingModel->update($force, $this->Auth->user());
            $message = __('Default decaying models updated');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('DecayingModel', 'update', false, $this->response->type(), $message);
            } else {
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'decayingModel', 'action' => 'index'));
            }
        } else {
            throw new MethodNotAllowedException(__("This method is not allowed"));
        }
    }

    public function export($model_id)
    {
        $model = $this->DecayingModel->fetchModel($this->Auth->user(), $model_id, true);
        if (empty($model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        unset($model['DecayingModel']['id'], $model['DecayingModel']['uuid'], $model['DecayingModel']['org_id'], $model['DecayingModelMapping']);
        return $this->RestResponse->viewData($model, 'application/json');
    }

    public function import()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->data['DecayingModel'];
            $text = FileAccessTool::getTempUploadedFile($data['submittedjson'], $data['json']);
            $json = json_decode($text, true);
            if ($json === null) {
                throw new MethodNotAllowedException(__('Error while decoding JSON'));
            }

            unset($json['id']);
            unset($json['uuid']);
            $json['default'] = 0;
            $json['org_id'] = $this->Auth->user()['org_id'];

            $attribute_types = array();
            if (!empty($json['attribute_types'])) {
                $attribute_types = $json['attribute_types'];
                unset($json['attribute_types']);
            }

            if ($this->DecayingModel->save($json)) {
                $saved_model = array(
                    'model_id' => $this->DecayingModel->id,
                    'attribute_types' => $attribute_types
                );
                if (!empty($saved_model['attribute_types'])) {
                    $result = $this->DecayingModel->DecayingModelMapping->resetMappingForModel($saved_model, $this->Auth->user());
                } else {
                    $result = true;
                }
                if (!empty($result)) {
                    $this->Flash->success(__('The model has been imported.'));
                } else {
                    $this->Flash->error(__('The model has been imported. However importing mapping failed.'));
                }
            } else {
                $this->Flash->error(__('Error while importing model.'));
            }
            $this->redirect(array('action' => 'index'));
        }
    }

    public function view($id)
    {
        $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $id, true);
        if (empty($decaying_model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        $this->set('id', $id);
        $this->set('decaying_model', $decaying_model);
        $available_formulas = $this->DecayingModel->listAvailableFormulas();
        $this->set('available_formulas', $available_formulas);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($decaying_model, 'application/json');
        }
    }

    // Sets pagination condition for url parameters
    private function __setIndexFilterConditions($passedArgs)
    {
        $white_list_url_parameters = array('sort', 'direction');
        $passedArgsArray = array();
        foreach ($passedArgs as $k => $v) {
            switch ($k) {
                case 'my_models':
                    $passedArgsArray[$k] = $v;
                    if ($v) {
                        $this->paginate['conditions']['AND'] = array('DecayingModel.org_id' => $this->Auth->user('Organisation')['id']);
                    }
                    break;
                case 'default_models':
                    $passedArgsArray[$k] = $v;
                    if ($v) {
                        $this->paginate['conditions']['AND'] = array('not' => array('DecayingModel.uuid' => null));
                    }
                    break;
                case 'all_orgs':
                    $passedArgsArray[$k] = $v;
                    if ($v) {
                        $this->paginate['conditions']['AND'] = array('DecayingModel.all_orgs' => $v);
                    }
                    break;
                default:
                    if (in_array($k, $white_list_url_parameters)) {
                        $passedArgsArray[$k] = $v;
                    }
                    break;
            }
        }
        return $passedArgsArray;
    }

    public function index()
    {
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions['OR'] = array(
                'org_id' => $this->Auth->user('Organisation')['id'],
                'all_orgs' => 1
            );
            $this->paginate = Set::merge($this->paginate, array(
                'conditions' => $conditions
            ));
        }
        $passedArgsArray = $this->__setIndexFilterConditions($this->passedArgs);
        $this->set('passedArgsArray', $passedArgsArray);
        $this->set('decayingModels', $this->paginate());
        $available_formulas = $this->DecayingModel->listAvailableFormulas();
        $this->set('available_formulas', $available_formulas);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($this->paginate(), 'application/json');
        }
    }

    public function add()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['DecayingModel'])) {
                $this->request->data = array('DecayingModel' => $this->request->data);
            }

            $this->request->data['DecayingModel']['org_id'] = $this->Auth->user()['org_id'];
            unset($this->request->data['DecayingModel']['id']);
            unset($this->request->data['DecayingModel']['uuid']);
            $this->request->data['DecayingModel']['default'] = 0;

            if (empty($this->request->data['DecayingModel']['name'])) {
                throw new MethodNotAllowedException(__("The model must have a name"));
            }
            $this->request->data = $this->__adjustJSONData($this->request->data);
            if ($this->request->data === false) {
                return false;
            }
            $attribute_types = array();
            if (!empty($this->request->data['attribute_types'])) {
                $attribute_types = $this->request->data['attribute_types'];
                unset($this->request->data['attribute_types']);
            }
            if ($this->DecayingModel->save($this->request->data)) {
                $success_message = __('The model has been saved.');
                if (!empty($saved_model['attribute_types'])) {
                    if (!$this->DecayingModel->DecayingModelMapping->resetMappingForModel($saved_model, $this->Auth->user())) {
                        $success_message = __('The model has been saved. However importing mapping failed.');
                    }
                }
                if ($this->request->is('ajax') || $this->_isRest()) {
                    $saved = $this->DecayingModel->fetchModel($this->Auth->user(), $this->DecayingModel->id, true, array(), true);
                    if (empty($saved)) {
                        throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
                    }
                    $response = array('data' => $saved, 'action' => 'add');
                    return $this->RestResponse->viewData($response, 'application/json');
                } else {
                    $this->Flash->success($success_message);
                    $this->redirect(array('action' => 'index'));
                }
            } else {
                if ($this->request->is('ajax') || $this->_isRest()) {
                    $response = array(
                        'action' => 'add',
                        'saved' => false,
                        'errors' => array(__('The model could not be saved. Please try again.'))
                    );
                    return $this->RestResponse->viewData($response, 'application/json');
                } else {
                    $this->Flash->error(__('The model could not be saved. Please try again.' . $this->here));
                    $this->redirect($this->here);
                }
            }
        } else {
            $this->set('action', 'add');
            $available_formulas = $this->DecayingModel->listAvailableFormulas();
            $formulas = array();
            foreach ($available_formulas as $formulaName => $f) {
                $formulas[$formulaName] = $formulaName;
            }
            $this->set('available_formulas', $formulas);
        }
    }

    public function edit($id)
    {
        $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
        if (empty($decaying_model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        $enforceRestrictedEdition = $decaying_model['DecayingModel']['default'];

        if ($this->request->is('post') || $this->request->is('put')) {

            $this->request->data['DecayingModel']['id'] = $id;
            $fieldListToSave = array('enabled', 'all_orgs');
            if (!$enforceRestrictedEdition) {
                $fieldListToSave = array_merge($fieldListToSave, array('name', 'description', 'parameters', 'formula'));
                $this->request->data = $this->__adjustJSONData($this->request->data);
                if ($this->request->data === false) {
                    return false;
                }
            }

            $save_result = $this->DecayingModel->save($this->request->data, true, $fieldListToSave);
            if ($save_result) {
                if ($this->request->is('ajax') || $this->_isRest()) {
                    $saved = $this->DecayingModel->fetchModel($this->Auth->user(), $this->DecayingModel->id, true, array(), true);
                    if (empty($saved)) {
                        throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
                    }
                    $response = array('data' => $saved, 'action' => 'edit');
                    return $this->RestResponse->viewData($response, $this->response->type());
                } else {
                    $this->Flash->success(__('The model has been saved.'));
                    $this->redirect(array('action' => 'index'));
                }
            } else {
                if ($this->request->is('ajax') || $this->_isRest()) {
                    $saved = $this->DecayingModel->fetchModel($this->Auth->user(), $this->DecayingModel->id);
                    if (empty($saved)) {
                        throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
                    }
                    $response = array('data' => $saved, 'action' => 'edit', 'saved' => false);
                    return $this->RestResponse->viewData($response, 'application/json');
                } else {
                    $this->Flash->error(__('The model could not be saved. Please try again.' . $this->here));
                    $this->redirect($this->here);
                }
            }
        } else {
            $this->request->data = $decaying_model;
            $this->set('id', $id);
            $this->set('decayingModel', $decaying_model);
            $this->set('restrictEdition', $enforceRestrictedEdition);
            $this->set('action', 'edit');
            $available_formulas = $this->DecayingModel->listAvailableFormulas();
            $formulas = array();
            foreach ($available_formulas as $formulaName => $f) {
                $formulas[$formulaName] = $formulaName;
            }
            $this->set('available_formulas', $formulas);
            $this->render('add');
        }
    }

    // Adjust or flash the error to the user
    private function __adjustJSONData($json)
    {
        if (isset($json['DecayingModel']['parameters'])) {
            if (isset($json['DecayingModel']['parameters']['settings']) && !is_array($json['DecayingModel']['parameters']['settings'])) {
                $settings = json_decode($json['DecayingModel']['parameters']['settings'], true);
                if ($settings === null) {
                    $this->Flash->error(__('Invalid JSON `Settings`.'));
                    return false;
                }
                $json['DecayingModel']['parameters']['settings'] = $settings;
            }
            if (!isset($json['DecayingModel']['parameters']['lifetime'])) {
                $this->Flash->error(__('Invalid parameter `lifetime`.'));
                return false;
            }
            if (!isset($json['DecayingModel']['parameters']['decay_speed'])) {
                $this->Flash->error(__('Invalid parameter `decay_speed`.'));
                return false;
            }
            if (!isset($json['DecayingModel']['parameters']['threshold'])) {
                $this->Flash->error(__('Invalid parameter `threshold`.'));
                return false;
            }
            if (!isset($json['DecayingModel']['parameters']['default_base_score'])) {
                $this->Flash->error(__('Invalid parameter `default_base_score`.'));
                return false;
            }
            if (isset($json['DecayingModel']['parameters']['base_score_config']) && $json['DecayingModel']['parameters']['base_score_config'] != '') {
                if (!is_array($json['DecayingModel']['parameters']['base_score_config'])) {
                    $encoded = json_decode($json['DecayingModel']['parameters']['base_score_config'], true);
                    if ($encoded === null) {
                        $this->Flash->error(__('Invalid parameter `base_score_config`.'));
                        return false;
                    }
                    $json['DecayingModel']['parameters']['base_score_config'] = $encoded;
                }
            } else {
                $json['DecayingModel']['parameters']['base_score_config'] = new stdClass();
            }
        } else {
            $this->Flash->error(__('Missing JSON key `parameters`.'));
            return false;
        }
        $json['DecayingModel']['parameters'] = json_encode($json['DecayingModel']['parameters']);
        return $json;
    }

    public function delete($id)
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
            if (empty($decaying_model)) {
                throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
            }
            if (
                !$this->DecayingModel->isEditableByCurrentUser($this->Auth->user(), $decaying_model) ||
                $decaying_model['DecayingModel']['default']
            ) {
                throw new MethodNotAllowedException(__('You are not authorised to delete this model.'));
            }

            if ($this->DecayingModel->delete($id, true)) {
                if ($this->request->is('ajax')) {
                    $response = array('action' => 'delete', 'saved' => true);
                    return $this->RestResponse->viewData($response, 'application/json');
                } else {
                    $this->Flash->success(__('Decaying Model deleted.'));
                }
            } else {
                $error_message = __('The Decaying Model could not be deleted.');
                if ($this->request->is('ajax')) {
                    $response = array('action' => 'delete', 'saved' => false, 'errors' => array($error_message));
                    return $this->RestResponse->viewData($response, 'application/json');
                } else {
                    $this->Flash->error($error_message);
                }
            }
            $this->redirect(array('action' => 'index'));
        }
    }

    public function enable($id)
    {
        $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
        if (empty($decaying_model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!$this->DecayingModel->isEditableByCurrentUser($this->Auth->user(), $decaying_model)) {
                throw new MethodNotAllowedException(__('You are not authorised to enable this model.'));
            }

            $decaying_model['DecayingModel']['enabled'] = 1;
            if ($this->DecayingModel->save($decaying_model)) {
                $model = $this->DecayingModel->fetchModel($this->Auth->user(), $id, true, array(), true);
                if (empty($model)) {
                    throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
                }
                $response = array('data' => $model, 'action' => 'enable');
                if ($this->request->is('ajax')) {
                    return $this->RestResponse->viewData($response, 'application/json');
                } else if ($this->_isRest()) {
                    return $this->RestResponse->successResponse($id, __('Decaying model enabled'), $model);
                }
                $this->Flash->success(__('Decaying Model enabled.'));
            } else {
                if ($this->request->is('ajax')) { // ajax caller expect data to be returned to update the DOM accordingly
                    $model = $this->DecayingModel->fetchModel($this->Auth->user(), $id, true, array(), true);
                    if (empty($model)) {
                        throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
                    }
                    $response = array('data' => $model, 'action' => 'enable');
                    return $this->RestResponse->viewData($response, 'application/json');
                } elseif ($this->_isRest()) {
                    $response = array('errors' => $array(__('Error while enabling decaying model')), 'action' => 'enable');
                    return $this->RestResponse->viewData($response, 'application/json');
                }
                $this->Flash->error(__('Error while enabling decaying model'));
            }
            $this->redirect(array('action' => 'index'));
        } else {
            $this->set('model', $decaying_model['DecayingModel']);
            $this->render('ajax/enable_form');
        }
    }

    public function disable($id)
    {
        $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
        if (empty($decaying_model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!$this->DecayingModel->isEditableByCurrentUser($this->Auth->user(), $decaying_model)) {
                throw new MethodNotAllowedException(__('You are not authorised to disable this model.'));
            }

            $decaying_model['DecayingModel']['enabled'] = 0;
            if ($this->DecayingModel->save($decaying_model)) {
                $model = $this->DecayingModel->fetchModel($this->Auth->user(), $id, true, array(), true);
                if (empty($model)) {
                    throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
                }
                $response = array('data' => $model, 'action' => 'disable');
                if ($this->request->is('ajax')) {
                    return $this->RestResponse->viewData($response, 'application/json');
                } else if ($this->_isRest()) {
                    return $this->RestResponse->successResponse($id, __('Decaying model disabled'), $model);
                }
                $this->Flash->success(__('Decaying Model disabled.'));
            } else {
                if ($this->request->is('ajax')) { // ajax caller expect data to be returned to update the DOM accordingly
                    $model = $this->DecayingModel->fetchModel($this->Auth->user(), $id, true, array(), true);
                    if (empty($model)) {
                        throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
                    }
                    $response = array('data' => $model, 'action' => 'disable');
                    return $this->RestResponse->viewData($response, 'application/json');
                } elseif ($this->_isRest()) {
                    $response = array('errors' => $array(__('Error while enabling decaying model')), 'action' => 'disable');
                    return $this->RestResponse->viewData($response, 'application/json');
                }
                $this->Flash->error(__('Error while disabling decaying model'));
            }
            $this->redirect(array('action' => 'index'));
        } else {
            $this->set('model', $decaying_model['DecayingModel']);
            $this->render('ajax/disable_form');
        }
    }

    public function decayingTool()
    {
        $parameters = array(
            'lifetime' => array(
                'value' => 30,
                'step' => 1,
                'max' => 365,
                'greek' => '',
                'unit' => 'days',
                'name' => __('Lifetime'),
                'info' => __('Lifetime of the attribute, or time after which the score will be 0')
            ),
            'decay_speed' => array(
                'value' => 0.3,
                'step' => 0.1,
                'max' => 10,
                'greek' => '',
                'name' => __('Decay speed'),
                'info' => __('Decay speed at which an indicator will loose score')
            ),
            'threshold' => array(
                'value' => 30,
                'step' => 1,
                'max' => 100,
                'greek' => '',
                'name' => __('Cutoff threshold'),
                'info' => __('Cutoff value at which an indicator will be marked as decayed instead of 0')
            )
        );
        $types = $this->User->Event->Attribute->typeDefinitions;
        $this->loadModel('ObjectTemplateElement');
        $objectTypes = $this->ObjectTemplateElement->getAllAvailableTypes();
        array_walk($objectTypes, function(&$item, $key) use ($types) {
            $item["isObject"] = true;
            $isAttribute = isset($types[$key]);
            if ($isAttribute) {
                $item["isAttribute"] = true;
                $item["default_category"] = $types[$key]['default_category'];
                $item["to_ids"] = $types[$key]['to_ids'];
            } else {
                $item["default_category"] = $item["category"];
            }
        });
        $types = array_merge($types, $objectTypes);
        ksort($types);
        $savedDecayingModels = $this->DecayingModel->fetchAllAllowedModels($this->Auth->user());
        $available_formulas = $this->DecayingModel->listAvailableFormulas();

        $this->set('available_formulas', $available_formulas);
        $this->set('parameters', $parameters);
        $this->set('types', $types);
        $this->set('savedModels', $savedDecayingModels);
        $associated_models = $this->DecayingModel->DecayingModelMapping->getAssociatedModels($this->Auth->user()); // mapping Attribute.type => Models
        $this->set('associated_models', $associated_models);
    }

    public function getAllDecayingModels()
    {
        $filters = $this->request->query;
        $savedDecayingModels = $this->DecayingModel->fetchAllAllowedModels($this->Auth->user(), true, $filters);
        return $this->RestResponse->viewData($savedDecayingModels, 'application/json');
    }

    public function decayingToolBasescore()
    {
        $taxonomies = $this->DecayingModel->listTaxonomiesWithNumericalValue();
        $this->set('taxonomies', $taxonomies['taxonomies']);
        $this->set('taxonomies_not_having_numerical_value', $taxonomies['not_having_numerical_value']);
        $this->set('excluded_taxonomies', $taxonomies['excluded_taxonomies']);
    }

    public function decayingToolSimulation($model_id)
    {
        $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $model_id);
        if (empty($decaying_model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        if (isset($this->request->params['named']['attribute_id'])) {
            $this->set('attribute_id', $this->request->params['named']['attribute_id']);
        }
        $this->set('user', $this->Auth->user());
        $this->set('decaying_model', $decaying_model);
        $allowed_models = $this->DecayingModel->fetchAllAllowedModels($this->Auth->user());
        $this->set('all_models', $allowed_models);
    }

    // TODO: Consider using the export tool to perform the post treatement
    // as this does not mirror a complete restSearch (not using fetchAttribute)
    public function decayingToolRestSearch($continue = false)
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $body = $this->request->data['decayingToolRestSearch']['filters'];
            $decoded_body = json_decode($body, true);
            if (is_null($decoded_body)) {
                throw new Exception(__("Error Processing Request, can't parse the body"));
            }
            $this->request->data = $decoded_body;
            $paramArray = array(
                'value' , 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp',
                'timestamp', 'enforceWarninglist', 'to_ids', 'deleted', 'includeEventUuid', 'event_timestamp', 'threat_level_id', 'includeEventTags',
                'includeProposals', 'returnFormat', 'published', 'limit', 'page', 'requested_attributes', 'includeContext', 'headerless',
                'includeWarninglistHits', 'attackGalaxy', 'object_relation', 'id', 'includeDecayScore', 'includeFullModel', 'decayingModel', 'excludeDecayed', 'modelOverrides',
                'score'
            );
            $filterData = array(
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'paramArray' => $paramArray,
                'ordered_url_params' => compact($paramArray)
            );
            $exception = false;
            $filters = $this->_harvestParameters($filterData, $exception);
            if ($filters === false) {
                return $exception;
            }
            $filters['includeEventTags'] = 1;
            if (!isset($filters['excludeDecayed'])) {
                $filters['excludeDecayed'] = 0;
            }
            $filters['includeDecayScore'] = 1;
            if (isset($filters['id'])) { // allows searching by id
                if (Validation::uuid($filters['id'])) {
                    $filters['uuid'] = $filters['id'];
                } else {
                    $attributes = $this->User->Event->Attribute->fetchAttributes($this->Auth->user(), array(
                        'conditions' => array('Attribute.id' => $filters['id']),
                        'flatten' => 1
                    ));
                    if (!empty($attributes)) {
                        $filters['uuid'] = $attributes[0]['Attribute']['uuid'];
                    } else {
                        $filters['uuid'] = '-1'; // force no result
                    }
                }
                unset($filters['id']);
            }
            unset($filterData);
            $this->Session->write('search_attributes_filters', json_encode($filters));
        } elseif ($continue === 'results') {
            $filters = $this->Session->read('search_attributes_filters');
            if (empty($filters)) {
                $filters = array();
            } else {
                $filters = json_decode($filters, true);
            }
        }
        if (isset($filters)) {
            $params = $this->User->Event->Attribute->restSearch($this->Auth->user(), 'json', $filters, true);
            if (!isset($params['conditions']['Attribute.deleted'])) {
                $params['conditions']['Attribute.deleted'] = 0;
            }
            $this->paginate = $params;
            if (empty($this->paginate['limit'])) {
                $this->paginate['limit'] = 60;
            }
            if (empty($this->paginate['page'])) {
                $this->paginate['page'] = 1;
            }
            $this->paginate['recursive'] = -1;
            $this->paginate['contain'] = array(
                'Event' => array(
                    'fields' =>  array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.info', 'Event.user_id', 'Event.date'),
                    'Orgc' => array('fields' => array('Orgc.id', 'Orgc.name')),
                    'Org' => array('fields' => array('Org.id', 'Org.name'))
                ),
                'AttributeTag' => array('Tag'),
                'Object' => array(
                    'fields' => array('Object.id', 'Object.distribution', 'Object.sharing_group_id')
                )
            );
            $attributes = $this->paginate($this->User->Event->Attribute);

            if (!empty($options['overrideLimit'])) {
                $overrideLimit = true;
            } else {
                $overrideLimit = false;
            }
            $this->loadModel('GalaxyCluster');
            $cluster_names = $this->GalaxyCluster->find('list', array('fields' => array('GalaxyCluster.tag_name'), 'group' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id')));
            $this->loadModel('Sighting');
            $eventTags = array();
            foreach ($attributes as $k => $attribute) {
                $attributes[$k]['Attribute']['AttributeTag'] = $attributes[$k]['AttributeTag'];
                $attributes[$k]['Attribute'] = $this->User->Event->massageTags($this->Auth->user(), $attributes[$k]['Attribute'], 'Attribute');
                unset($attributes[$k]['AttributeTag']);
                foreach ($attributes[$k]['Attribute']['AttributeTag'] as $k2 => $attributeTag) {
                    if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                        unset($attributes[$k]['Attribute']['AttributeTag'][$k2]);
                    }
                }
                if (!empty($params['includeEventTags'])) {
                    $tagConditions = array('EventTag.event_id' => $attribute['Event']['id']);
                    if (empty($params['includeAllTags'])) {
                        $tagConditions['Tag.exportable'] = 1;
                    }
                    $temp = $this->User->Event->EventTag->find('all', array(
                        'recursive' => -1,
                        'contain' => array('Tag'),
                        'conditions' => $tagConditions
                    ));
                    foreach ($temp as $tag) {
                        $attributes[$k]['Attribute']['EventTag'][] = $tag;
                    }
                }
                if (empty($filters['decayingModel'])) {
                    $filters['decayingModel'] = false;
                }
                $model_overrides = isset($filters['modelOverrides']) ? $filters['modelOverrides'] : array();
                if (isset($filters['score'])) {
                    $model_overrides['threshold'] = intval($filters['score']);
                }
                $attributes[$k]['Attribute'] = $this->DecayingModel->attachScoresToAttribute($this->Auth->user(), $attributes[$k]['Attribute'], $filters['decayingModel'], $model_overrides);
                if ($filters['excludeDecayed'] && !empty($attributes[$k]['Attribute']['decay_score'])) { // filter out decayed attribute
                    $decayed_flag = true;
                    foreach ($attributes[$k]['Attribute']['decay_score'] as $decayResult) {
                        $decayed_flag = $decayed_flag && $decayResult['decayed'];
                    }
                    if ($decayed_flag) {
                        unset($attributes[$k]);
                    }
                }
            }
            $this->set('sightingsData', $this->Sighting->attributesStatistics($attributes, $this->Auth->user()));
            $this->set('attributes', $attributes);
            $this->set('attrDescriptions', $this->User->Event->Attribute->fieldDescriptions);
            $this->set('typeDefinitions', $this->User->Event->Attribute->typeDefinitions);
            $this->set('categoryDefinitions', $this->User->Event->Attribute->categoryDefinitions);
            $this->set('shortDist', $this->User->Event->Attribute->shortDist);
        } else {
            $this->render('decayingToolRestSearchForm');
        }
    }

    public function decayingToolComputeSimulation($model_id, $attribute_id)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__("This method is only accessible via AJAX."));
        }
        $model_overrides = array();
        if (isset($this->params['named']['modelOverride'])) {
            $model_overrides = $this->params['named']['modelOverride'];
            $model_overrides = json_decode($model_overrides, true);
            if ($model_overrides === null) {
                $model_overrides = array();
            }
        }
        if (isset($this->params['named']['score'])) {
            $model_overrides['threshold'] = intval($this->params['named']['score']);
        }
        $score_overtime = $this->DecayingModel->getScoreOvertime($this->Auth->user(), $model_id, $attribute_id, $model_overrides);
        return $this->RestResponse->viewData($score_overtime, 'application/json');
    }
}
