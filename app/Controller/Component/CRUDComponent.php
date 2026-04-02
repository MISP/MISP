<?php
class CRUDComponent extends Component
{
    /** @var AppController */
    public $Controller;

    public function initialize(Controller $controller, $settings=array())
    {
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
        $quickFilterParameter = empty($options['quickFilterParameter']) ? 'quickFilter' : $options['quickFilterParameter'];
        if (!empty($options[$quickFilterParameter])) {
            if (empty($options['filters'])) {
                $options['filters'] = [];
            }
            $options['filters'][] = $options[$quickFilterParameter];
        }
        $this->Controller->{$this->Controller->modelClass}->includeAnalystData = true;
        $foundQuickFilter = false;
        if (!empty($options['filters'])) {
            foreach ($options['filters'] as $filter) {
                if ($filter === $quickFilterParameter) {
                    $foundQuickFilter = true;
                    continue;
                }
            }
            if (!$foundQuickFilter && !empty($options['quickFilters'])) {
                $options['filters'][] = $quickFilterParameter;
            }
        }
        $params = $this->Controller->IndexFilter->harvestParameters(empty($options['filters']) ? [] : $options['filters']);
        $query = [];
        $query = $this->setFilters($params, $query, $quickFilterParameter);
        $query = $this->setQuickFilters($params, $query, empty($options['quickFilters']) ? [] : $options['quickFilters'], $quickFilterParameter);
        if (!empty($options['contain'])) {
            $query['contain'] = $options['contain'];
        }
        if (!empty($options['conditions'])) {
            $query['conditions']['AND'][] = $options['conditions'];
        }
        if (!empty($options['order'])) {
            $query['order'] = $options['order'];
        } else if (!empty($this->Controller->paginate['order'])) {
            $query['order'] = $this->Controller->paginate['order'];
        }
        if ($this->Controller->IndexFilter->isRest()) {
            if (!empty($this->Controller->paginate['fields'])) {
                $query['fields'] = $this->Controller->paginate['fields'];
            }
            $query['includeAnalystData'] = true;
            $data = $this->Controller->{$this->Controller->modelClass}->find('all', $query);
            if (isset($options['afterFind'])) {
                if (is_callable($options['afterFind'])) {
                    $data = $options['afterFind']($data);
                } else {
                    $data = $this->Controller->{$this->Controller->modelClass}->{$options['afterFind']}($data);
                }
            }
            $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
        } else {
            $query['includeAnalystData'] = true;
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
        $modelName = $this->Controller->modelClass;
        $data = [];
        if ($this->Controller->request->is('post') || $this->Controller->request->is('put')) {
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
            if (isset($params['beforeSave'])) {
                $data = $params['beforeSave']($data);
            }
            /** @var Model $model */
            $model = $this->Controller->{$modelName};
            $model->create();
            $savedData = $model->save($data);
            if ($savedData) {
                if (isset($params['afterSave'])) {
                    $params['afterSave']($savedData);
                }
                $data = $model->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'id' => $model->id
                    ]
                ]);
                if (empty($data)) {
                    throw new Exception("Something went wrong, saved data not found in database.");
                }
                if (isset($params['afterFind'])) {
                    $data = $params['afterFind']($data, $savedData);
                }
                $message = __('%s added.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
                } else {
                    $this->Controller->Flash->success($message);
                    if (!empty($params['displayOnSuccess'])) {
                        $this->Controller->set('entity', $data);
                        $this->Controller->set('referer', $this->Controller->referer(['action' => 'view', $model->id], true));
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
                $message = __('%s could not be added. Errors %s', $modelName, implode(', ', Hash::flatten($model->validationErrors)));
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
        $modelName = $this->Controller->modelClass;
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
        if (empty($data)) {
            throw new NotFoundException(__('Invalid %s.', $modelName));
        }
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
                    if(isset($input[$modelName][$field])){
                        $data[$modelName][$field] = $input[$modelName][$field];
                    }
                }
            } else {
                foreach ($input[$modelName] as $field => $fieldData) {
                    $data[$modelName][$field] = $fieldData;
                }
            }
            if (isset($params['beforeSave'])) {
                $data = $params['beforeSave']($data);
            }
            if ($data = $model->save($data)) {
                if (isset($params['afterSave'])) {
                    $params['afterSave']($data);
                }
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
        $modelName = $this->Controller->modelClass;
        if (empty($id)) {
            throw new NotFoundException(__('Invalid %s.', $modelName));
        }
        $this->Controller->{$modelName}->includeAnalystData = true;
        $this->Controller->{$modelName}->includeAnalystDataRecursive = true;
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
        $modelName = $this->Controller->modelClass;
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
        if (isset($params['afterFind'])) {
            $data = $params['afterFind']($data);
        }
        if (isset($params['beforeDelete'])) {
            $data = $params['beforeDelete']($data);
            if (empty($data)) {
                throw new MethodNotAllowedException('Something went wrong, delete action failed.');
            }
        }
        if ($validationError === null && $this->Controller->request->is('post') || $this->Controller->request->is('delete')) {
            if (!empty($params['modelFunction'])) {
                $result = $this->Controller->$modelName->{$params['modelFunction']}($id);
            } else {
                $result = $this->Controller->{$modelName}->delete($id);
            }
            if ($result) {
                if (isset($params['afterDelete']) && is_callable($params['afterDelete'])) {
                    $params['afterDelete']($data);
                }
                $message = __('%s deleted.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->saveSuccessResponse($modelName, 'delete', $id, 'json', $message);
                    return;
                } else {
                    $this->Controller->Flash->success($message);
                    $redirect = isset($params['redirect']) ? $params['redirect'] : ['action' => 'index'];
                    if (!empty($params['redirect_controller'])) {
                        if (is_array($redirect)) {
                            $redirect['controller'] = $params['redirect_controller'];
                        } else {
                            $redirect = '/' . $params['redirect_controller'] . '/' . $redirect;
                        }
                    }
                    $this->Controller->redirect($this->Controller->referer($redirect));
                }
            } else {
                if ($this->Controller->IndexFilter->isRest()) {
                    $validationError = __('%s could not be deleted.', $modelName);
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->saveFailResponse($modelName, 'delete', $id, $validationError);
                    return;
                }
            }
        }
        $this->Controller->set('validationError', $validationError);
        $this->Controller->set('id', $data[$modelName]['id']);
        $this->Controller->set('data', $data);
        $this->Controller->layout = 'ajax';
        $this->Controller->render('/genericTemplates/delete');
    }

    public function setQuickFilters($params, array $query, $quickFilterFields, $quickFilterParameter = 'quickFilter')
    {
        if (!empty($params[$quickFilterParameter]) && !empty($quickFilterFields)) {
            $queryConditions = [];
            $filter = '%' . strtolower($params[$quickFilterParameter]) . '%';
            foreach ($quickFilterFields as $filterField) {
                $queryConditions["LOWER($filterField) LIKE"] = $filter;
            }
            $query['conditions']['OR'] = $queryConditions;
        }
        return $query;
    }

    public function setFilters(array $params, array $query, $quickFilterParameter = 'quickFilter')
    {
        // For CakePHP 2, we don't need to distinguish between simpleFilters and relatedFilters
        //$params = $this->massageFilters($params);
        if (!empty($params)) {
            foreach ($params as $filter => $filterValue) {
                if ($filter === $quickFilterParameter) {
                    continue;
                }
                if (is_array($filterValue)) {
                    $query['conditions']['AND'][] = [$filter => $filterValue];
                } else if (strlen(trim($filterValue, '%')) === strlen($filterValue)) {
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
                    if ($param[0] === $this->Controller->{$this->Controller->modelClass}) {
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

    public function deleteSelection($id = null, array $options = [])
    {
        $this->prepareResponse();
        $modelName = $options['modelName'] ?? $this->Controller->modelClass;
        $restName = $options['restName'] ?? $modelName . 's';
        $itemName = $options['itemName'] ?? strtolower($modelName);
        $viewPath = $options['view'] ?? 'ajax/' . strtolower($modelName) . 'DeleteConfirmationForm';

        $Model = $this->Controller->{$modelName};

        if ($this->Controller->request->is(['post', 'put', 'delete'])) {
            if (isset($this->Controller->request->data['id'])) {
                $this->Controller->request->data[$modelName] = $this->Controller->request->data;
            }
            if (!isset($id) && isset($this->Controller->request->data[$modelName]['id'])) {
                $idList = $this->Controller->request->data[$modelName]['id'];
                if (!is_array($idList)) {
                    if (is_numeric($idList) || Validation::uuid($idList)) {
                        $idList = [$idList];
                    } else {
                        $idList = json_decode($idList, true);
                    }
                }
                if (empty($idList)) {
                    throw new NotFoundException(__('Invalid input.'));
                }
            } else {
                $idList = [$id];
            }
            $successes = [];
            $fails = [];
            foreach ($idList as $cid) {
                $item = $Model->find('first', [
                    'conditions' => Validation::uuid($cid)
                        ? [$modelName . '.uuid' => $cid]
                        : [$modelName . '.id' => $cid],
                    'recursive' => -1,
                ]);
                if (empty($item)) {
                    $fails[] = $cid;
                    continue;
                }

                $itemId = $item[$modelName]['id'];
                $canModify = true;
                if (isset($options['checkModifyCallback']) && is_callable($options['checkModifyCallback'])) {
                    $canModify = call_user_func($options['checkModifyCallback'], $itemId, $item);
                }

                if (!$canModify) {
                    $fails[] = $cid;
                    continue;
                }
                if ($Model->delete($itemId)) {
                    $successes[] = $cid;
                } else {
                    $fails[] = $cid;
                }
            }
            if (count($idList) === 1) {
                $message = empty($successes)
                    ? __('%s was not deleted.', ucfirst($itemName))
                    : __('%s deleted.', ucfirst($itemName));
            } else {
                $message = '';
                if (!empty($successes)) {
                    if (isset($options['multiSuccessMessageCallback']) && is_callable($options['multiSuccessMessageCallback'])) {
                        $message .= call_user_func($options['multiSuccessMessageCallback'], count($successes));
                    } else {
                        $message .= count($successes) . ' ' . $itemName . '(s) deleted.';
                    }
                }
                if (!empty($fails)) {
                    $message .= ' ' . count($fails) . ' ' . $itemName . '(s) could not be deleted due to insufficient privileges or not found.';
                }
            }
            if (isset($this->Controller->IndexFilter) && $this->Controller->IndexFilter->isRest()) {
                if (!empty($successes)) {
                    return $this->Controller->RestResponse->saveSuccessResponse(
                        $restName, 'delete', $id, $this->Controller->response->type(), $message
                    );
                } else {
                    return $this->Controller->RestResponse->saveFailResponse(
                        $restName, 'delete', false, $message, $this->Controller->response->type()
                    );
                }
            }
            if (!empty($successes)) {
                $this->Controller->Flash->success(trim($message));
            } else {
                $this->Controller->Flash->error(trim($message));
            }
            return $this->Controller->redirect(['action' => 'index']);
        } else {
            $itemList = is_numeric($id) ? [$id] : json_decode($id, true);
            $this->Controller->request->data[$modelName]['id'] = json_encode($itemList);
            $this->Controller->set('idArray', $itemList);
            $this->Controller->layout = false;
            return $this->Controller->render($viewPath);
        }
    }

}
