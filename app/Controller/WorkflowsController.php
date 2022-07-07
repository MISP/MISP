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
        $requirementErrors = [];
        if (empty(Configure::read('MISP.background_jobs'))) {
            $requirementErrors[] = __('Background workers must be enabled to use workflows');
            $this->render('error');
        }
        if (empty(Configure::read('Plugin.Workflow_enable'))) {
            $requirementErrors[] = __('The workflow plugin must be enabled to use workflows. Go to `/servers/serverSettings/Plugin` the enable the `Plugin.Workflow` setting');
            $this->render('error');
        }
        try {
            $this->Workflow->setupRedisWithException();
        } catch (Exception $e) {
            $requirementErrors[] = $e->getMessage();
        }
        if (!empty($requirementErrors)) {
            $this->set('requirementErrors', $requirementErrors);
            $this->render('error');
        }
    }

    public function index()
    {
        $params = [
            'filters' => ['name', 'uuid'],
            'quickFilters' => ['name', 'uuid'],
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'index'));
    }

    public function rebuildRedis()
    {
        $this->Workflow->rebuildRedis();
    }

    public function edit($id)
    {
        $this->set('id', $id);
        $savedWorkflow = $this->Workflow->fetchWorkflow($id);
        if ($this->request->is('post') || $this->request->is('put')) {
            $newWorkflow = $this->request->data;
            $newWorkflow['Workflow']['data'] = JsonTool::decode($newWorkflow['Workflow']['data']);
            $newWorkflow = $this->__applyDataFromSavedWorkflow($newWorkflow, $savedWorkflow);
            $errors = $this->Workflow->editWorkflow($newWorkflow);
            $redirectTarget = ['action' => 'view', $id];
            if (!empty($errors)) {
                return $this->__getFailResponseBasedOnContext($errors, null, 'edit', $this->Workflow->id, $redirectTarget);
            } else {
                $successMessage = __('Workflow saved.');
                $savedWorkflow =$this->Workflow->fetchWorkflow($id);
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
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function view($id)
    {
        $this->CRUD->view($id, [
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'view'));
    }

    public function editor($trigger_id)
    {
        $modules = $this->Workflow->getModulesByType();
        $trigger_ids = Hash::extract($modules['blocks_trigger'], '{n}.id');
        if (!in_array($trigger_id, $trigger_ids)) {
            return $this->__getFailResponseBasedOnContext(
                [__('Unkown trigger %s', $trigger_id)],
                null,
                'add',
                $trigger_id,
                ['controller' => 'workflows', 'action' => 'triggers']
            );
        }
        $workflow = $this->Workflow->fetchWorkflowByTrigger($trigger_id, false);
        if (empty($workflow)) { // Workflow do not exists yet. Create it.
            $this->Workflow->create();
            $savedWorkflow = $this->Workflow->save([
                'name' => sprintf('Workflow for trigger %s', $trigger_id),
                'trigger_id' => $trigger_id,
            ]);
            if (empty($savedWorkflow)) {
                return $this->__getFailResponseBasedOnContext(
                    [__('Could not create workflow for trigger %s', $trigger_id), $this->Workflow->validationErrors],
                    null,
                    'add',
                    $trigger_id,
                    ['controller' => 'workflows', 'action' => 'editor']
                );
            }
            $workflow = $savedWorkflow;
        }
        $modules = $this->Workflow->attachNotificationToModules($modules, $workflow);
        $this->loadModel('WorkflowBlueprint');
        $workflowBlueprints = $this->WorkflowBlueprint->find('all');
        $this->set('selectedWorkflow', $workflow);
        $this->set('modules', $modules);
        $this->set('workflowBlueprints', $workflowBlueprints);
    }

    public function triggers()
    {
        $triggers = $this->Workflow->getModulesByType('trigger');
        $triggers = $this->Workflow->attachWorkflowToTriggers($triggers);
        $data = $triggers;
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        }
        $this->set('data', $data);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'index_trigger']);
    }

    public function moduleIndex()
    {
        $modules = $this->Workflow->getModulesByType();
        $this->Module = ClassRegistry::init('Module');
        $mispModules = $this->Module->getModules('Action');
        $this->set('module_service_error', !is_array($mispModules));
        $filters = $this->IndexFilter->harvestParameters(['type', 'actiontype', 'enabled']);
        $moduleType = $filters['type'] ?? 'action';
        $actionType = $filters['actiontype'] ?? 'all';
        $enabledState = $filters['enabled'] ?? false;
        if ($moduleType == 'all' || $moduleType == 'custom') {
            $data = array_merge(
                $modules["blocks_action"],
                $modules["blocks_logic"]
            );
        } else {
            $data = $modules["blocks_{$moduleType}"];
        }
        if ($actionType == 'mispmodule') {
            $data = array_filter($data, function($module) {
                return !empty($module['is_misp_module']);
            });
        } else if ($actionType == 'blocking') {
            $data = array_filter($data, function ($module) {
                return !empty($module['is_blocking']);
            });
        } else if ($moduleType == 'custom') {
            $data = array_filter($data, function ($module) {
                return !empty($module['is_custom']);
            });
        }
        if ($enabledState !== false) {
            $moduleType = !empty($enabledState) ? 'enabled' : 'disabled';
            $data = array_filter($data, function ($module) use ($enabledState) {
                return !empty($enabledState) ? empty($module['disabled']) : !empty($module['disabled']);
            });
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        }
        $this->set('data', $data);
        $this->set('indexType', $moduleType);
        $this->set('actionType', $actionType);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'index_module']);
    }

    public function moduleView($module_id)
    {
        $module = $this->Workflow->getModuleByID($module_id);
        if (empty($module)) {
            throw new NotFoundException(__('Invalid trigger ID'));
        }
        $is_trigger = $module['module_type'] == 'trigger';
        if ($is_trigger) {
            $module = $this->Workflow->attachWorkflowToTriggers([$module])[0];
            $module['listening_workflows'] = $this->Workflow->getListeningWorkflowForTrigger($module);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($module, $this->response->type());
        }
        $this->set('data', $module);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'view_module']);
    }

    public function toggleModule($module_id, $enabled, $is_trigger=false)
    {
        $this->request->allowMethod(['post', 'put']);
        $saved = $this->Workflow->toggleModule($module_id, $enabled, $is_trigger);
        if ($saved) {
            return $this->__getSuccessResponseBasedOnContext(
                __('%s module %s', ($enabled ? 'Enabled' : 'Disabled'), $module_id),
                null,
                'toggle_module',
                $module_id,
                ['action' => (!empty($is_trigger) ? 'triggers' : 'moduleIndex')]
            );
        } else {
            return $this->__getFailResponseBasedOnContext(
                __('Could not %s module %s', ($enabled ? 'Enabled' : 'Disabled'), $module_id),
                null,
                'toggle_module',
                $module_id,
                ['action' => (!empty($is_trigger) ? 'triggers' : 'moduleIndex')]
            );
        }
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
            $this->redirect($redirect);
        }
    }

    private function __applyDataFromSavedWorkflow($newWorkflow, $savedWorkflow)
    {
        if (!isset($newReport['Workflow'])) {
            $newReport = ['Workflow' => $newWorkflow];
        }
        $ignoreFieldList = ['id', 'uuid'];
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
        $graphData = JsonTool::decode($this->request->data['graph']);
        $cycles = [];
        $isAcyclic = $this->Workflow->workflowGraphTool->isAcyclic($graphData, $cycles);
        $data = [
            'is_acyclic' => $isAcyclic,
            'cycles' => $cycles,
        ];
        return $this->RestResponse->viewData($data, 'json');
    }
}
