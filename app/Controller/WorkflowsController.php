<?php
App::uses('AppController', 'Controller');

class WorkflowsController extends AppController
{
    public $components = array(
        'RequestHandler'
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions[] = 'hasAcyclicGraph';
        try {
            $this->Workflow->setupRedisWithException();
        } catch (Exception $e) {
            $this->set('error', $e->getMessage());
            $this->render('error');
        }
    }

    public function index()
    {
        $params = [
            'filters' => ['name', 'uuid'],
            'quickFilters' => ['name', 'uuid'],
            'contain' => ['Organisation']
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'index'));
    }

    // public function test($id)
    // {
    //     // $this->Workflow->rebuildRedis($this->Auth->user());
    //     // return $this->RestResponse->viewData($ret);
    //     $workflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
    //     // $ret = $this->Workflow->walkGraph($workflow);
    //     // $workflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
    //     // $ret = $this->Workflow->getModulesByType();

    //     // $ret = $this->Workflow->executeWorkflowsForTrigger('publish', ['foo' => 'bar']);
    //     // $ret = $this->Workflow->executeWorkflow($id);
    //     $this->set('error', '');
    //     return $this->render('error');
    // }

    public function rebuildRedis()
    {
        $this->Workflow->rebuildRedis($this->Auth->user());
    }

    public function add()
    {
        $currentUser = $this->Auth->user();
        $params = [
            'beforeSave' => function ($data) use ($currentUser) {
                if (empty($data['Workflow']['uuid'])) {
                    $data['Workflow']['uuid'] = CakeText::uuid();
                }
                $data['Workflow']['user_id'] = $currentUser['id'];
                $data['Workflow']['org_id'] = $currentUser['org_id'];
                if (!isset($data['Workflow']['description'])) {
                    $data['Workflow']['description'] = '';
                }
                if (!empty($data['Workflow']['data'])) {
                    $data['Workflow']['data'] = JsonTool::decode($data['Workflow']['data']);
                } else {
                    $data['Workflow']['data'] = [];
                }
                return $data;
            },
            'redirect' => [
                'action' => 'index',
            ]
        ];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'add'));
    }

    public function edit($id)
    {
        $this->set('id', $id);
        $savedWorkflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
        if ($this->request->is('post') || $this->request->is('put')) {
            $newWorkflow = $this->request->data;
            $newWorkflow['Workflow']['data'] = JsonTool::decode($newWorkflow['Workflow']['data']);
            $newWorkflow = $this->__applyDataFromSavedWorkflow($newWorkflow, $savedWorkflow);
            $errors = $this->Workflow->editWorkflow($this->Auth->user(), $newWorkflow);
            $redirectTarget = ['action' => 'view', $id];
            if (!empty($errors)) {
                return $this->__getFailResponseBasedOnContext($errors, null, 'edit', $this->Workflow->id, $redirectTarget);
            } else {
                $successMessage = __('Workflow saved.');
                $savedWorkflow =$this->Workflow->fetchWorkflow($this->Auth->user(), $id);
                return $this->__getSuccessResponseBasedOnContext($successMessage, $savedWorkflow, 'edit', false, $redirectTarget);
            }
        } else {
            $savedWorkflow['Workflow']['data'] = JsonTool::encode($savedWorkflow['Workflow']['data']);
            $this->request->data = $savedWorkflow;
        }

        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'edit'));
        $this->render('add');
    }

    public function delete($id)
    {
        $params = [
            'conditions' => $this->Workflow->buildACLConditions($this->Auth->user()),
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function view($id)
    {
        $this->CRUD->view($id, [
            'conditions' => $this->Workflow->buildACLConditions($this->Auth->user()),
            'contain' => ['Organisation', 'User']
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'view'));
    }

    public function enable($id)
    {
        $errors = $this->Workflow->toggleWorkflow($this->Auth->user(), $id, true);
        $redirectTarget = ['action' => 'index'];
        if (!empty($errors)) {
            return $this->__getFailResponseBasedOnContext($errors, null, 'edit', $this->Workflow->id, $redirectTarget);
        } else {
            $successMessage = __('Workflow enabled.');
            $savedWorkflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
            return $this->__getSuccessResponseBasedOnContext($successMessage, $savedWorkflow, 'edit', false, $redirectTarget);
        }
    }

    public function disable($id)
    {
        $errors = $this->Workflow->toggleWorkflow($this->Auth->user(), $id, false);
        $redirectTarget = ['action' => 'index'];
        if (!empty($errors)) {
            return $this->__getFailResponseBasedOnContext($errors, null, 'edit', $this->Workflow->id, $redirectTarget);
        } else {
            $successMessage = __('Workflow disabled.');
            $savedWorkflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
            return $this->__getSuccessResponseBasedOnContext($successMessage, $savedWorkflow, 'edit', false, $redirectTarget);
        }
    }

    public function editor($id = false)
    {
        $modules = $this->Workflow->getModulesByType();
        $workflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
        $modules = $this->Workflow->attachNotificationToModules($this->Auth->user(), $modules, $workflow);
        $workflows = $this->Workflow->fetchWorkflows($this->Auth->user());
        $this->set('selectedWorkflow', $workflow);
        $this->set('workflows', $workflows);
        $this->set('modules', $modules);
    }

    public function moduleIndex()
    {
        $modules = $this->Workflow->getModulesByType();
        // FIXME: Apply ACL to filter out module not available to users
        $filters = $this->IndexFilter->harvestParameters(['type']);
        $moduleType = $filters['type'] ?? 'trigger';
        if ($moduleType == 'trigger') {
            $triggers = $modules['blocks_trigger'];
            $triggers = $this->Workflow->attachWorkflowsToTriggers($this->Auth->user(), $triggers, true);
            $data = $triggers;
        } elseif ($moduleType == 'all') {
            $data = array_merge(
                $modules["blocks_trigger"],
                $modules["blocks_logic"],
                $modules["blocks_action"]
            );
        } else {
            $data = $modules["blocks_{$moduleType}"];
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        }
        $this->set('data', $data);
        $this->set('indexType', $moduleType);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'index_module']);
    }

    public function moduleView($module_id)
    {
        $module = $this->Workflow->getModuleByID($module_id);
        if (empty($module)) {
            throw new NotFoundException(__('Invalid trigger ID'));
        }
        if ($module['module_type'] == 'trigger') {
            $module = $this->Workflow->attachWorkflowsToTriggers($this->Auth->user(), [$module], true)[0];
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($module, $this->response->type());
        }
        $this->set('data', $module);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'view_module']);
    }

    public function import()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->data['Workflow'];
            $text = FileAccessTool::getTempUploadedFile($data['submittedjson'], $data['json']);
            $workflow = JsonTool::decode($text);
            if ($workflow === null) {
                throw new MethodNotAllowedException(__('Error while decoding JSON'));
            }
            $workflow['Workflow']['enabled'] = false;
            $workflow['Workflow']['data'] = JsonTool::encode($workflow['Workflow']['data']);
            $this->request->data = $workflow;
            $this->add();
        }
    }

    public function export($id)
    {
        $workflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
        $content = JsonTool::encode($workflow, JSON_PRETTY_PRINT);
        $this->response->body($content);
        $this->response->type('json');
        $this->response->download(sprintf('workflow_%s_%s.json', $workflow['Workflow']['name'], time()));
        return $this->response;
    }

    public function rearrangeExecutionOrder($trigger_id)
    {
        $trigger = $this->Workflow->getModuleByID($trigger_id);
        if (empty($trigger)) {
            throw new NotFoundException(__('Invalid trigger ID'));
        }
        $trigger = $this->Workflow->attachWorkflowsToTriggers($this->Auth->user(), [$trigger], true)[0];
        $workflow_order = [];
        if (!empty($trigger['Workflows']['blocking'])) {
            $workflow_order = Hash::extract($trigger['Workflows']['blocking'], '{n}.Workflow.id');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $workflow_order = array_unique(JsonTool::decode($this->request->data['Workflow']['workflow_order']));
            $saved = $this->Workflow->saveBlockingWorkflowExecutionOrder($trigger['id'], $workflow_order);
            $redirectTarget = ['action' => 'triggerView', $trigger_id];
            if (empty($saved)) {
                return $this->__getFailResponseBasedOnContext([__('Could not save workflow execution order.')], null, 'rearrangeExecutionOrder', $trigger_id, $redirectTarget);
            } else {
                $successMessage = __('Workflow execution order saved.');
                return $this->__getSuccessResponseBasedOnContext($successMessage, $workflow_order, 'rearrangeExecutionOrder', false, $redirectTarget);
            }
        } else {
            $this->request->data = [
                'Workflow' => [
                    'workflow_order' => JsonTool::encode($workflow_order),
                ]
            ];
        }
        $this->set('trigger', $trigger);
    }

    private function __getSuccessResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
    {
        if ($this->_isRest()) {
            if (!is_null($data)) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveSuccessResponse('Workflow', $action, $id, false, $message);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveSuccessResponse('Workflow', $action, $id, false, $message, $data);
        } else {
            $this->Flash->success($message);
            $this->redirect($redirect);
        }
        return;
    }

    private function __getFailResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
    {
        if (is_array($message)) {
            $message = implode(', ', $message);
        }
        if ($this->_isRest()) {
            if ($data !== null) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('Workflow', $action, $id, $message);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveFailResponse('Workflow', $action, $id, $message, false, $data);
        } else {
            $this->Flash->error($message);
            $this->redirect($this->referer());
        }
    }

    private function __applyDataFromSavedWorkflow($newWorkflow, $savedWorkflow)
    {
        if (!isset($newReport['Workflow'])) {
            $newReport = ['Workflow' => $newWorkflow];
        }
        $ignoreFieldList = ['id', 'uuid', 'org_id', 'user_id'];
        foreach (Workflow::CAPTURE_FIELDS as $field) {
            if (!in_array($field, $ignoreFieldList) && isset($newWorkflow['Workflow'][$field])) {
                $savedWorkflow['Workflow'][$field] = $newWorkflow['Workflow'][$field];
            }
        }
        return $savedWorkflow;
    }

    public function hasAcyclicGraph()
    {
        $this->request->allowMethod(['post']);
        $graphData = $this->request->data;
        $cycles = [];
        $isAcyclic = $this->Workflow->workflowGraphTool->isAcyclic($graphData, $cycles);
        $data = [
            'is_acyclic' => $isAcyclic,
            'cycles' => $cycles,
        ];
        return $this->RestResponse->viewData($data, 'json');
    }
}
