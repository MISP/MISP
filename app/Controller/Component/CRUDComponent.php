<?php

class CRUDComponent extends Component
{
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

    public function index($options)
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
            $data = $this->Controller->{$this->Controller->defaultModel}->find('all', $query);
            $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
        } else {
            $this->Controller->paginate = $query;
            $data = $this->Controller->paginate();
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
            if (isset($input[$modelName]['id'])) {
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
            if ($this->Controller->{$modelName}->save($data)) {
                $data = $this->Controller->{$modelName}->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'id' => $this->Controller->{$modelName}->id
                    ]
                ]);
                if (!empty($params['saveModelVariable'])) {
                    foreach ($params['saveModelVariable'] as $var) {
                        if (isset($this->Controller->{$modelName}->$var)) {
                            $data[$modelName][$var] = $this->Controller->{$modelName}->$var;
                        }
                    }
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
                    $this->Controller->redirect(['action' => 'index']);
                }
            } else {
                $message = __('%s could not be added.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {

                } else {
                    $this->Controller->Flash->error($message);
                }
            }
        }
        $this->Controller->set('entity', $data);
    }

    public function edit(int $id, array $params = []): void
    {
        $modelName = $this->Controller->defaultModel;
        if (empty($id)) {
            throw new NotFoundException(__('Invalid %s.', $modelname));
        }
        $data = $this->Controller->{$modelName}->find('first',
            isset($params['get']) ? $params['get'] : [
                'recursive' => -1,
                'conditions' => [
                    'id' => $id
            ]
        ]);
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
                    $data[$field] = $input[$modelName][$field];
                }
            } else {
                foreach ($input as $field => $fieldData) {
                    $data[$field] = $fieldData;
                }
            }
            if ($this->Controller->{$modelName}->save($data)) {
                $message = __('%s updated.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
                } else {
                    $this->Controller->Flash->success($message);
                    $this->Controller->redirect(['action' => 'index']);
                }
            } else {
                if ($this->Controller->IndexFilter->isRest()) {

                }
            }
        }
        $this->Controller->set('entity', $data);
    }

    public function view(int $id, array $params = []): void
    {
        if (empty($id)) {
            throw new NotFoundException(__('Invalid {0}.', $this->ObjectAlias));
        }
        $modelName = $this->Controller->defaultModel;
        $data = $this->Controller->{$modelName}->find('first', [
            'recursive' => -1,
            'conditions' => array($modelName . '.id' => $id),
            'contain' => empty($params['contain']) ? [] : $params['contain']
        ]);
        if ($this->Controller->IndexFilter->isRest()) {
            $this->Controller->restResponsePayload = $this->Controller->RestResponse->viewData($data, 'json');
        } else {
            $this->Controller->set('data', $data);
        }
    }

    public function delete(int $id, array $params = []): void
    {
        $this->prepareResponse();
        $modelName = $this->Controller->defaultModel;
        if (empty($id)) {
            throw new NotFoundException(__('Invalid %s.', $modelname));
        }
        $conditions = [];
        $conditions['AND'][] = ['id' => $id];
        if (!empty($params['conditions'])) {
            $conditions['AND'][] = $params['conditions'];
        }
        $data = $this->Controller->{$modelName}->find('first', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
        if (empty($data)) {
            throw new NotFoundException(__('Invalid %s.', $modelname));
        }
        if ($this->Controller->request->is('post') || $this->Controller->request->is('delete')) {
            if ($this->Controller->{$modelName}->delete($id)) {
                $message = __('%s deleted.', $modelName);
                if ($this->Controller->IndexFilter->isRest()) {
                    $data = $this->Controller->{$modelName}->find('first', [
                        'recursive' => -1,
                        'conditions' => array('id' => $id)
                    ]);
                    $this->Controller->restResponsePayload = $this->Controller->RestResponse->saveSuccessResponse($modelname, 'delete', $id, 'json', $message);
                } else {
                    $this->Controller->Flash->success($message);
                    $this->Controller->redirect($this->Controller->referer());
                }
            }
        }
        $this->Controller->set('id', $data[$modelName]['id']);
        $this->Controller->set('data', $data);
        $this->Controller->layout = 'ajax';
        $this->Controller->render('/genericTemplates/delete');
    }


    protected function setQuickFilters($params, $query, $quickFilterFields)
    {
        $queryConditions = [];
        if (!empty($params['quickFilter']) && !empty($quickFilterFields)) {
            foreach ($quickFilterFields as $filterField) {
                $queryConditions[$filterField] = $params['quickFilter'];
            }
            $query['conditions']['OR'][] = $queryConditions;
        }
        return $query;
    }

    protected function setFilters($params, $query)
    {
        $params = $this->massageFilters($params);
        $conditions = array();
        if (!empty($params['simpleFilters'])) {
            foreach ($params['simpleFilters'] as $filter => $filterValue) {
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

    protected function massageFilters(array $params): array
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
