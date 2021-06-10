<?php

class CRUDComponent extends Component
{
    /** @var AppController */
    public $Controller = null;

    public function initialize(Controller $controller, $settings=array()) {
        $this->Controller = $controller;
    }

    private function prepareResponse()
    {
        if ($this->Controller->request->is('ajax')) {
            $this->Controller->set('ajax', true);
        }
    }

    public function index(array $options)
    {
        $this->prepareResponse();
        if (!empty($options['quickFilters'])) {
            if (empty($options['filters'])) {
                $options['filters'] = [];
            }
            $options['filters'][] = 'quickFilter';
        }
        $params = $this->Controller->IndexFilter->harvestParameters(empty($options['filters']) ? [] : $options['filters']);
        $query = [];
        $query = $this->setFilters($params, $query);
        $query = $this->setQuickFilters($params, $query, empty($options['quickFilters']) ? [] : $options['quickFilters']);
        if (!empty($options['contain'])) {
            $query['contain'] = $options['contain'];
        }
        if (!empty($options['conditions'])) {
            $query['conditions']['AND'][] = $options['conditions'];
        }
        if ($this->Controller->IndexFilter->isRest()) {
            if (!empty($this->Controller->paginate['fields'])) {
                $query['fields'] = $this->Controller->paginate['fields'];
            }
            $data = $this->Controller->{$this->Controller->defaultModel}->find('all', $query);
            if (isset($options['afterFind'])) {
                if (is_callable($options['afterFind'])) {
                    $data = $options['afterFind']($data);
                } else {
                    $data = $this->Controller->{$this->Controller->defaultModel}->{$options['afterFind']}($data);
                }
            }
            $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
        } else {
            $this->Controller->paginate = $query;
            $data = $this->Controller->paginate();
            if (isset($options['afterFind'])) {
                if (is_callable($options['afterFind'])) {
                    $data = $options['afterFind']($data);
                } else {
                    $data = $this->Controller->{$this->Controller->defaultModel}->{$options['afterFind']}($data);
                }
            }
            $this->Controller->set('data', $data);
        }
    }

    public function add(array $params = [])
    {
        $modelName = $this->Controller->defaultModel;
        $data = [];
        if ($this->Controller->request->is('post')) {
            $input = $this->Controller->request->data;
            if (empty($input[$modelName])) {
                $input = [$modelName => $input];
            }
            if (!empty($params['override'])) {
                foreach ($params['override'] as $field => $value) {
                    $input[$modelName][$field] = $value;
                }
            }
            unset($input[$modelName]['id']);
            if (!empty($params['fields'])) {
                $data = [];
                foreach ($params['fields'] as $field) {
                    $data[$field] = $input[$modelName][$field];
                }
            } else {
                $data = $input;
            }
            /** @var Model $model */
            $model = $this->Controller->{$modelName};
            if ($model->save($data)) {
                $data = $model->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'id' => $model->id
                    ]
                ]);
                if (!empty($params['saveModelVariable'])) {
                    foreach ($params['saveModelVariable'] as $var) {
                        if (isset($model->$var)) {
                            $data[$modelName][$var] = $model->$var;
                        }
                    }
                }
                if (isset($params['afterFind'])) {
                    $data = $params['afterFind']($data);
                }
                $message = __('%s added.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
                } else {
                    $this->Controller->Flash->success($message);
                    if (!empty($params['displayOnSuccess'])) {
                        $this->Controller->set('entity', $data);
                        $this->Controller->set('referer', $this->Controller->referer());
                        $this->Controller->render($params['displayOnSuccess']);
                        return;
                    }

                    $redirect = isset($params['redirect']) ? $params['redirect'] : ['action' => 'index'];
                    if (!empty($params['redirect_controller'])) {
                        if (is_array($redirect)) {
                            $redirect['controller'] = $params['redirect_controller'];
                        } else {
                            $redirect = '/' . $params['redirect_controller'] . '/' . $redirect;
                        }
                    }
                    // For AJAX requests doesn't make sense to redirect, redirect must be done on javascript side in `submitGenericFormInPlace`
                    if ($this->Controller->request->is('ajax')) {
                        $redirect = Router::url($redirect);
                        $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData(['redirect' => $redirect], 'json');
                    } else {
                        $this->Controller->redirect($redirect);
                    }
                }
            } else {
                $message = __('%s could not be added.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $controllerName = $this->Controller->params['controller'];
                    $actionName = $this->Controller->params['action'];
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->saveFailResponse($controllerName, $actionName, false, $model->validationErrors, 'json');
                } else {
                    $this->Controller->Flash->error($message);
                }
            }
        }
        $this->Controller->set('entity', $data);
    }

    public function edit(int $id, array $params = [])
    {
        $modelName = $this->Controller->defaultModel;
        if (empty($id)) {
            throw new NotFoundException(__('Invalid %s.', $modelName));
        }
        $query = isset($params['get']) ? $params['get'] : [
            'recursive' => -1,
            'conditions' => [
                $modelName . '.id' => $id
            ],
        ];
        if (!empty($params['conditions'])) {
            $query['conditions']['AND'][] = $params['conditions'];
        }
        if (!empty($params['contain'])) {
            $query['contain'] = $params['contain'];
        }
        /** @var Model $model */
        $model = $this->Controller->{$modelName};
        $data = $model->find('first', $query);
        if (isset($params['afterFind'])) {
            $data = $params['afterFind']($data);
        }
        if ($this->Controller->request->is('post') || $this->Controller->request->is('put')) {
            $input = $this->Controller->request->data;
            if (empty($input[$modelName])) {
                $input = [$modelName => $input];
            }
            if (!empty($params['override'])) {
                foreach ($params['override'] as $field => $value) {
                    $input[$field] = $value;
                }
            }
            if (!empty($params['fields'])) {
                foreach ($params['fields'] as $field) {
                    $data[$modelName][$field] = $input[$modelName][$field];
                }
            } else {
                foreach ($input[$modelName] as $field => $fieldData) {
                    $data[$modelName][$field] = $fieldData;
                }
            }
            if (isset($params['beforeSave'])) {
                $data = $params['beforeSave']($data);
            }
            if ($model->save($data)) {
                $message = __('%s updated.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
                    return;
                } else {
                    $this->Controller->Flash->success($message);
                    $this->Controller->redirect(isset($params['redirect']) ? $params['redirect'] : ['action' => 'index']);
                }
            } else {
                if ($this->Controller->IndexFilter->isRest()) {
                    $controllerName = $this->Controller->params['controller'];
                    $actionName = $this->Controller->params['action'];
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->saveFailResponse($controllerName, $actionName, false, $model->validationErrors, 'json');
                }
            }
        } else {
            $this->Controller->request->data = $data;
        }
        $this->Controller->set('entity', $data);
    }

    public function view(int $id, array $params = [])
    {
        $modelName = $this->Controller->defaultModel;
        if (empty($id)) {
            throw new NotFoundException(__('Invalid %s.', $modelName));
        }
        $query = [
            'recursive' => -1,
            'conditions' => [$modelName . '.id' => $id],
            'contain' => empty($params['contain']) ? [] : $params['contain']
        ];
        if (!empty($params['conditions'])) {
            $query['conditions']['AND'][] = $params['conditions'];
        }
        $data = $this->Controller->{$modelName}->find('first', $query);
        if (empty($data)) {
            throw new NotFoundException(__('Invalid %s.', $modelName));
        }
        if (isset($params['afterFind'])) {
            $data = $params['afterFind']($data);
        }
        if ($this->Controller->IndexFilter->isRest()) {
            $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
        } else {
            $this->Controller->set('data', $data);
        }
    }

    public function delete(int $id, array $params = [])
    {
        $this->prepareResponse();
        $modelName = $this->Controller->defaultModel;
        if (empty($id)) {
            throw new NotFoundException(__('Invalid %s.', $modelName));
        }
        $conditions = [];
        $conditions['AND'][] = [$modelName . '.id' => $id];
        if (!empty($params['conditions'])) {
            $conditions['AND'][] = $params['conditions'];
        }
        $data = $this->Controller->{$modelName}->find('first', [
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => empty($params['contain']) ? [] : $params['contain'],
        ]);
        if (empty($data)) {
            throw new NotFoundException(__('Invalid %s.', $modelName));
        }
        $validationError = null;
        if (isset($params['validate'])) {
            try {
                $params['validate']($data);
            } catch (Exception $e) {
                $validationError = $e->getMessage();
                if ($this->Controller->IndexFilter->isRest()) {
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->saveFailResponse($modelName, 'delete', $id, $validationError);
                }
            }
        }
        if ($validationError === null && $this->Controller->request->is('post') || $this->Controller->request->is('delete')) {
            if (!empty($params['modelFunction'])) {
                $result = $this->Controller->$modelName->{$params['modelFunction']}($id);
            } else {
                $result = $this->Controller->{$modelName}->delete($id);
            }
            if ($result) {
                $message = __('%s deleted.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->saveSuccessResponse($modelName, 'delete', $id, 'json', $message);
                    return;
                } else {
                    $this->Controller->Flash->success($message);
                    $this->Controller->redirect($this->Controller->referer());
                }
            }
        }
        $this->Controller->set('validationError', $validationError);
        $this->Controller->set('id', $data[$modelName]['id']);
        $this->Controller->set('data', $data);
        $this->Controller->layout = 'ajax';
        $this->Controller->render('/genericTemplates/delete');
    }

    public function setQuickFilters($params, array $query, $quickFilterFields)
    {
        if (!empty($params['quickFilter']) && !empty($quickFilterFields)) {
            $queryConditions = [];
            $filter = '%' . strtolower($params['quickFilter']) . '%';
            foreach ($quickFilterFields as $filterField) {
                $queryConditions["LOWER($filterField) LIKE"] = $filter;
            }
            $query['conditions']['OR'] = $queryConditions;
        }
        return $query;
    }

    public function setFilters(array $params, array $query)
    {
        // For CakePHP 2, we don't need to distinguish between simpleFilters and relatedFilters
        //$params = $this->massageFilters($params);
        if (!empty($params)) {
            foreach ($params as $filter => $filterValue) {
                if ($filter === 'quickFilter') {
                    continue;
                }
                if (strlen(trim($filterValue, '%')) === strlen($filterValue)) {
                    $query['conditions']['AND'][] = [$filter => $filterValue];
                } else {
                    $query['conditions']['AND'][] = [$filter . ' LIKE' => $filterValue];
                }
            }
        }
        /* Currently not implemented
        if (!empty($params['relatedFilters'])) {
            foreach ($params['relatedFilters'] as $filter => $filterValue) {
                $filterParts = explode('.', $filter);
                $query->matching($filterParts[0], function(\Cake\ORM\Query $q) use ($filterValue, $filter) {
                    if (strlen(trim($filterValue, '%')) === strlen($filterValue)) {
                        return $q->where([$filter => $filterValue]);
                    } else {
                        return $q->like([$filter => $filterValue]);
                    }
                });
            }
        }
        */
        return $query;
    }

    protected function massageFilters(array $params)
    {
        $massagedFilters = [
            'simpleFilters' => [],
            'relatedFilters' => []
        ];
        if (!empty($params)) {
            foreach ($params as $param => $paramValue) {
                if (strpos($param, '.') !== false) {
                    $param = explode('.', $param);
                    if ($param[0] === $this->Controller->{$this->Controller->defaultModel}) {
                        $massagedFilters['simpleFilters'][implode('.', $param)] = $paramValue;
                    } else {
                        $massagedFilters['relatedFilters'][implode('.', $param)] = $paramValue;
                    }
                } else {
                    $massagedFilters['simpleFilters'][$param] = $paramValue;
                }
            }
        }
        return $massagedFilters;
    }
}
