<?php

App::uses('AppController', 'Controller');

class DecayingModelController extends AppController
{
    public $components = array('Security' ,'RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'DecayingModel.name' => 'asc'
            )
    );

    public function update($force=false)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException(__('You are not authorised to edit it.'));
        }

        if ($this->request->is('post')) {
            $this->DecayingModel->update($force);
            $message = 'Default decaying models updated';
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
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new MethodNotAllowedException(__('No Decaying Model with the provided ID exists, or you are not authorised to view it.'));
        }
        unset($model['DecayingModel']['id']);
        unset($model['DecayingModel']['org_id']);
        unset($model['DecayingModelMapping']);
        return $this->RestResponse->viewData($model, $this->response->type());
    }

    public function import()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->data['DecayingModel'];
            if ($data['submittedjson']['name'] != '' && $data['json'] != '') {
                throw new MethodNotAllowedException(__('Only one import field can be used'));
            }
            if ($data['submittedjson']['size'] > 0) {
                $filename = basename($data['submittedjson']['name']);
                $file_content = file_get_contents($data['submittedjson']['tmp_name']);
                if ((isset($data['submittedjson']['error']) && $data['submittedjson']['error'] == 0) ||
                    (!empty($data['submittedjson']['tmp_name']) && $data['submittedjson']['tmp_name'] != '')
                ) {
                    if (!$file_content) {
                        throw new InternalErrorException(__('PHP says file was not uploaded. Are you attacking me?'));
                    }
                }
                $text = $file_content;
            } else {
                $text = $data['json'];
            }
            $json = json_decode($text, true);
            if ($json === null) {
                throw new MethodNotAllowedException(__('Error while decoding JSON'));
            }
            if ($this->DecayingModel->save($json)) {
                $this->Flash->success(__('The model has been saved.'));
            } else {
                $this->Flash->error(__('Error while saving model.'));
            }
            $this->redirect(array('action' => 'index'));
        }
    }

    public function view($id)
    {
        if (!$this->request->is('get')) {
            throw new MethodNotAllowedException("This method is not allowed");
        }

        $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $id, true);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new MethodNotAllowedException(__('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
        }
        $this->set('mayModify', true);
        $this->set('id', $id);
        $this->set('decaying_model', $decaying_model);
    }

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
            $conditions['OR'] = array('org_id' => $this->Auth->user('Organisation')['id']);
        }
        if (!$this->_isSiteAdmin()) {
            $this->paginate = Set::merge($this->paginate, array(
                'conditions' => $conditions
            ));
        }
        $passedArgsArray = $this->__setIndexFilterConditions($this->passedArgs);
        $this->set('passedArgsArray', $passedArgsArray);
        $this->set('decayingModel', $this->paginate());
    }

    public function add()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['DecayingModel']['org_id'])) {
                $this->request->data['DecayingModel']['org_id'] = $this->Auth->user()['org_id'];
            }

            if (empty($this->request->data['DecayingModel']['name'])) {
                throw new MethodNotAllowedException(__("The model must have a name"));
            }

            if ($this->DecayingModel->save($this->request->data)) {
                if ($this->request->is('ajax')) {
                    $saved = $this->DecayingModel->fetchModel($this->Auth->user(), $this->DecayingModel->id);
                    $response = array('data' => $saved, 'action' => 'add');
                    return $this->RestResponse->viewData($response, $this->response->type());
                } else {
                    $this->Flash->success(__('The model has been saved.'));
                    $this->redirect(array('action' => 'index'));
                }
            }
        } else {
            $this->set('action', 'add');
        }
    }

    public function edit($id)
    {
        $decayingModel = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
        }
        $this->set('mayModify', true);
        $restrictedEdition = $this->DecayingModel->isDefaultModel($decayingModel);

        if ($this->request->is('post') || $this->request->is('put')) {

            $this->request->data['DecayingModel']['id'] = $id;
            $fieldList = array('enabled', 'all_orgs');
            if (!$restrictedEdition) {
                $fieldList += array('name', 'description', 'parameters', 'formula');

                if (!isset($this->request->data['DecayingModel']['formula'])) {
                    $this->request->data['DecayingModel']['formula'] = 'polynomial';
                }

                if ($this->request->data['DecayingModel']['formula'] == 'polynomial') {
                    if (isset($this->request->data['DecayingModel']['parameters']['settings'])) {
                        $this->request->data['DecayingModel']['parameters']['settings'] = '{}';
                    }
                } else if (
                    isset($this->request->data['DecayingModel']['parameters']['settings']) &&
                    $this->request->data['DecayingModel']['parameters']['settings'] == ''
                ) {
                    $this->request->data['DecayingModel']['parameters']['settings'] = '{}';
                }

                if (isset($this->request->data['DecayingModel']['parameters'])) {
                    if (isset($this->request->data['DecayingModel']['parameters']['settings'])) {
                        $settings = json_decode($this->request->data['DecayingModel']['parameters']['settings'], true);
                        if ($settings === null) {
                            $this->Flash->error(__('Invalid JSON `Settings`.'));
                            return false;
                        }
                        $this->request->data['DecayingModel']['parameters']['settings'] = $settings;
                    }
                    if (!isset($this->request->data['DecayingModel']['parameters']['tau'])) {
                        $this->Flash->error(__('Invalid parameter `tau`.'));
                        return false;
                    }
                    if (!isset($this->request->data['DecayingModel']['parameters']['delta'])) {
                        $this->Flash->error(__('Invalid parameter `delta`.'));
                        return false;
                    }
                    if (!isset($this->request->data['DecayingModel']['parameters']['threshold'])) {
                        $this->Flash->error(__('Invalid parameter `threshold`.'));
                        return false;
                    }
                    if (!isset($this->request->data['DecayingModel']['parameters']['default_base_score'])) {
                        $this->Flash->error(__('Invalid parameter `default_base_score`.'));
                        return false;
                    }
                    if (isset($this->request->data['DecayingModel']['parameters']['base_score_config']) && $this->request->data['DecayingModel']['parameters']['base_score_config'] != '') {
                        $encoded = json_decode($this->data['DecayingModel']['parameters']['base_score_config'], true);
                        if ($encoded === null) {
                            $this->Flash->error(__('Invalid parameter `base_score_config`.'));
                            return false;
                        }
                        $this->request->data['DecayingModel']['parameters']['base_score_config'] = $encoded;
                    } else {
                        $this->request->data['DecayingModel']['parameters']['base_score_config'] = new stdClass();
                    }
                }

                $this->request->data['DecayingModel']['parameters'] = json_encode($this->request->data['DecayingModel']['parameters']);
            }

            $save_result = $this->DecayingModel->save($this->request->data, true, $fieldList);
            if ($save_result) {
                if ($this->request->is('ajax')) {
                    $saved = $this->DecayingModel->fetchModel($this->Auth->user(), $this->DecayingModel->id);
                    $response = array('data' => $saved, 'action' => 'edit');
                    return $this->RestResponse->viewData($response, $this->response->type());
                } else {
                    $this->Flash->success(__('The model has been saved.'));
                    $this->redirect(array('action' => 'index'));
                }
            } else {
                if ($this->request->is('ajax')) {
                    $saved = $this->DecayingModel->fetchModel($this->Auth->user(), $this->DecayingModel->id);
                    $response = array('data' => $saved, 'action' => 'edit', 'saved' => false);
                    return $this->RestResponse->viewData($response, $this->response->type());
                } else {
                    $this->Flash->error(__('The model could not be saved. Please try again.' . $this->here));
                    $this->redirect($this->here);
                }
            }
        } else {
            $this->request->data = $decayingModel;
            $this->set('id', $id);
            $this->set('decayingModel', $decayingModel);
            $this->set('restrictEdition', $restrictedEdition);
            $this->set('action', 'edit');
            $this->render('add');
        }
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $decayingModel = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
            if (!$this->_isSiteAdmin() && !$decModel) {
                throw new MethodNotAllowedException(__('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
            }

            if ($this->DecayingModel->delete($id, true)) {
                $this->Flash->success(__('Decaying Model deleted.'));
            } else {
                $this->Flash->error(__('The Decaying Model could not be deleted.'));
            }
            $this->redirect(array('action' => 'index'));
        }
    }

    public function enable($id)
    {
        $decayingModel = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new MethodNotAllowedException(__('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $original_value_enabled = $decayingModel['DecayingModel']['enabled'];
            $decayingModel['DecayingModel']['enabled'] = 1;
            if ($this->DecayingModel->save($decayingModel)) {
                if ($this->request->is('ajax')) {
                    $response = array('data' => $this->DecayingModel->fetchModel($this->Auth->user(), $id), 'action' => 'edit');
                    return $this->RestResponse->viewData($response, $this->response->type());
                }
                $this->Flash->success(__('Decaying Model enabled.'));
            } else {
                if ($this->request->is('ajax')) {
                    $response = array('data' => $this->DecayingModel->fetchModel($this->Auth->user(), $id), 'action' => 'edit');
                    return $this->RestResponse->viewData($response, $this->response->type());
                }
                $this->Flash->error(__('Error while enabling decaying model'));
            }
            $this->redirect(array('action' => 'index'));
        } else {
            $this->set('model', $decayingModel['DecayingModel']);
            $this->render('ajax/enable_form');
        }
    }

    public function disable($id)
    {
        $decayingModel = $this->DecayingModel->fetchModel($this->Auth->user(), $id);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new MethodNotAllowedException(__('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $original_value_enabled = $decayingModel['DecayingModel']['enabled'];
            $decayingModel['DecayingModel']['enabled'] = 0;
            if ($this->DecayingModel->save($decayingModel)) {
                if ($this->request->is('ajax')) {
                    $response = array('data' => $this->DecayingModel->fetchModel($this->Auth->user(), $id), 'action' => 'edit');
                    return $this->RestResponse->viewData($response, $this->response->type());
                }
                $this->Flash->success(__('Decaying Model disabled.'));
            } else {
                if ($this->request->is('ajax')) {
                    $response = array('data' => $this->DecayingModel->fetchModel($this->Auth->user(), $id), 'action' => 'edit');
                    return $this->RestResponse->viewData($response, $this->response->type());
                }
                $this->Flash->error(__('Error while disabling decaying model'));
            }
            $this->redirect(array('action' => 'index'));
        } else {
            $this->set('model', $decayingModel['DecayingModel']);
            $this->render('ajax/disable_form');
        }
    }

    public function decayingTool()
    {
        $parameters = array(
            'Tau' => array('value' => 30, 'step' => 1, 'max' => 365, 'greek' => 'τ', 'unit' => 'days', 'name' => 'Lifetime', 'info' => 'Lifetime of the attribute, or time after which the score will be 0'),
            'Delta' => array('value' => 0.3, 'step' => 0.1, 'max' => 10, 'greek' => 'δ', 'name' => 'Decay speed', 'info' => 'Decay speed at which an indicator will loose score'),
            'Threshold' => array('value' => 30, 'step' => 1, 'name' =>'Cutoff threshold', 'info' => 'Cutoff value at which an indicator will be marked as decayed instead of 0')
        );
        $types = $this->User->Event->Attribute->typeDefinitions;
        // $types = array_filter($types, function($v, $k) {
        //     return $v['to_ids'] == 1;
        // }, ARRAY_FILTER_USE_BOTH);
        $this->loadModel('ObjectTemplateElement');
        $objectTypes = $this->ObjectTemplateElement->getAllAvailableTypes();
        array_walk($objectTypes, function(&$key) {
            $key["isObject"] = true;
            $key["default_category"] = $key["category"];
        });
        $types = array_merge($types, $objectTypes);
        ksort($types);
        $savedDecayingModels = $this->DecayingModel->fetchAllAllowedModels($this->Auth->user());
        $available_formulas = $this->DecayingModel->listAvailableFormulas();

        $this->set('available_formulas', $available_formulas);
        $this->set('parameters', $parameters);
        $this->set('types', $types);
        $this->set('savedModels', $savedDecayingModels);
        $associated_models = $this->DecayingModel->DecayingModelMapping->getAssociatedModels($this->Auth->user());
        $this->set('associated_models', $associated_models);
        $associated_types = array();
        foreach ($associated_models as $type => $models) {
            foreach (array_keys($models) as $model_id) {
                $associated_types[$model_id][] = $type;
            }
        }
        $this->set('associated_types', $associated_types);
    }

    public function getAllDecayingModels()
    {
        if ($this->request->is('get') && $this->request->is('ajax')) {
            $savedDecayingModels = $this->DecayingModel->fetchAllAllowedModels($this->Auth->user());
            $associated_models = $this->DecayingModel->DecayingModelMapping->getAssociatedModels($this->Auth->user());
            $associated_types = array();
            foreach ($associated_models as $type => $models) {
                foreach (array_keys($models) as $model_id) {
                    $associated_types[$model_id][] = $type;
                }
            }
            return $this->RestResponse->viewData(array(
                'associated_types' => $associated_types,
                'savedDecayingModels' => $savedDecayingModels
            ), $this->response->type());
        } else {
            throw new MethodNotAllowedException(__("This method is only accessible via AJAX."));
        }
    }

    public function decayingToolBasescore()
    {
        $taxonomies = $this->DecayingModel->listTaxonomiesWithNumericalValue();
        $this->set('taxonomies', $taxonomies['taxonomies']);
        $this->set('taxonomies_not_having_numerical_value', $taxonomies['not_having_numerical_value']);
    }

    public function decayingToolSimulation($model_id)
    {
        $decaying_model = $this->DecayingModel->fetchModel($this->Auth->user(), $model_id);
        if (!$decaying_model) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
        }
        if (isset($this->request->params['named']['attribute_id'])) {
            $this->set('attribute_id', $this->request->params['named']['attribute_id']);
        }
        $this->set('user', $this->Auth->user());
        $this->set('decaying_model', $decaying_model);
        $allowed_models = $this->DecayingModel->fetchAllAllowedModels($this->Auth->user());
        $this->set('all_models', $allowed_models);
    }

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
                'includeWarninglistHits', 'attackGalaxy', 'object_relation', 'id', 'includeDecayScore', 'decayingModel', 'excludeDecayed', 'modelOverrides'
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
            if (!isset($filters['includeEventTags'])) {
                $filters['includeEventTags'] = 1;
            }
            if (!isset($filters['excludeDecayed'])) {
                $filters['excludeDecayed'] = 0;
            }
            $filters['includeDecayScore'] = 1;
            if (isset($filters['id'])) { // alows searched by id
                if (Validation::uuid($filters['id'])) {
                    $filters['uuid'] = $filters['id'];
                } else {
                    $attributes = $this->User->Event->Attribute->fetchAttributesSimple($this->Auth->user(), array(
                        'conditions' => array('id' => $filters['id'])
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

            // attach sightings and massage tags
            $sightingsData = array();
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
                $attributes[$k]['Attribute'] = $this->User->Event->massageTags($attributes[$k]['Attribute'], 'Attribute');
                unset($attributes[$k]['AttributeTag']);
                foreach ($attributes[$k]['Attribute']['AttributeTag'] as $k2 => $attributeTag) {
                    if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                        unset($attributes[$k]['Attribute']['AttributeTag'][$k2]);
                    }
                }
                $sightingsData = array_merge(
                    $sightingsData,
                    $this->Sighting->attachToEvent($attribute, $this->Auth->user(), $attributes[$k]['Attribute']['id'], $extraConditions = false)
                );
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
                $this->DecayingModel->attachScoresToAttribute($this->Auth->user(), $attributes[$k]['Attribute'], $filters['decayingModel'], $model_overrides);
                if ($filters['excludeDecayed']) { // filter out decayed attribute
                    $decayed_flag = true;
                    foreach ($attributes[$k]['Attribute']['decay_score'] as $decayResult) {
                        $decayed_flag = $decayed_flag && $decayResult['decayed'];
                    }
                    if ($decayed_flag) {
                        unset($attributes[$k]);
                    }
                }
            }
            $sightingsData = $this->User->Event->getSightingData(array('Sighting' => $sightingsData));
            $this->set('sightingsData', $sightingsData);
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
        // contain score overtime, sightings, and base_score computation
        $results = $this->DecayingModel->getScoreOvertime($this->Auth->user(), $model_id, $attribute_id, $model_overrides);
        return $this->RestResponse->viewData($results, $this->response->type());
    }
}
