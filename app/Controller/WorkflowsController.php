<?php
App::uses('AppController', 'Controller');

class WorkflowsController extends AppController
{
    public $components = array(
        'RequestHandler'
    );

    private $toggleableFields = ['enabled'];

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions[] = 'checkGraph';
        $this->Security->unlockedActions[] = 'moduleStatelessExecution';
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
            $result = $this->Workflow->editWorkflow($newWorkflow);
            $redirectTarget = ['action' => 'view', $id];
            if (!empty($result['errors'])) {
                return $this->__getFailResponseBasedOnContext($result['errors'], null, 'edit', $this->Workflow->id, $redirectTarget);
            } else {
                $successMessage = __('Workflow saved.');
                $savedWorkflow = $result['saved'];
                $savedWorkflow = $this->Workflow->attachLabelToConnections($savedWorkflow);
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
        $filters = $this->IndexFilter->harvestParameters(['format']);
        if (!empty($filters['format'])) {
            if ($filters['format'] == 'dot') {
                $dot = $this->Workflow->getDotNotation($id);
                return $this->RestResponse->viewData($dot, $this->response->type());
            } else if ($filters['format'] == 'mermaid') {
                $mermaid = $this->Workflow->getMermaid($id);
                return $this->RestResponse->viewData($mermaid, $this->response->type());
            }
        }
        $this->CRUD->view($id, [
            'afterFind' => function($workflow) {
                return $this->Workflow->attachLabelToConnections($workflow);
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'view'));
    }

    public function editor($id)
    {
        $trigger_id = false;
        $workflow = false;
        if (is_numeric($id)) {
            $workflow_id = $id;
        } else {
            $trigger_id = $id;
        }
        $modules = $this->Workflow->getModulesByType();
        if (!empty($trigger_id)) {
            $trigger_ids = Hash::extract($modules['modules_trigger'], '{n}.id');
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
                $result = $this->Workflow->addWorkflow([
                    'name' => sprintf('Workflow for trigger %s', $trigger_id),
                    'data' => $this->Workflow->genGraphDataForTrigger($trigger_id),
                    'trigger_id' => $trigger_id,
                ]);
                if (!empty($result['errors'])) {
                    return $this->__getFailResponseBasedOnContext(
                        [__('Could not create workflow for trigger %s', $trigger_id), $result['errors']],
                        null,
                        'add',
                        $trigger_id,
                        ['controller' => 'workflows', 'action' => 'editor']
                    );
                }
                $workflow = $this->Workflow->fetchWorkflowByTrigger($trigger_id, false);
            }
        } else {
            $workflow = $this->Workflow->fetchWorkflow($workflow_id);
        }
        $workflow = $this->Workflow->attachLabelToConnections($workflow, $trigger_id);
        $modules = $this->Workflow->attachNotificationToModules($modules, $workflow);
        $this->loadModel('WorkflowBlueprint');
        $workflowBlueprints = $this->WorkflowBlueprint->find('all');
        $workflowBlueprints = array_map(function($blueprint) {
            return $this->WorkflowBlueprint->attachModuleDataToBlueprint($blueprint);
        }, $workflowBlueprints);
        $this->set('selectedWorkflow', $workflow);
        $this->set('workflowTriggerId', $trigger_id);
        $this->set('modules', $modules);
        $this->set('workflowBlueprints', $workflowBlueprints);
    }

    public function executeWorkflow($workflow_id)
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $blockingErrors = [];
            if (!JsonTool::isValid($this->request->data['Workflow']['data'])) {
                return $this->RestResponse->viewData([
                    'success' => false,
                    'outcome' => __('Invalid JSON'),
                ], $this->response->type());
            }
            $data = JsonTool::decode($this->request->data['Workflow']['data']);
            $result = $this->Workflow->executeWorkflow($workflow_id, $data, $blockingErrors);
            if (!empty($logging) && empty($result['success'])) {
                $logging['message'] = !empty($logging['message']) ? $logging['message'] : __('Error while executing workflow.');
                $errorMessage = implode(', ', $blockingErrors);
                $this->Workflow->loadLog()->createLogEntry('SYSTEM', $logging['action'], $logging['model'], $logging['id'], $logging['message'], __('Returned message: %s', $errorMessage));
            }
            return $this->RestResponse->viewData([
                'success' => $result['success'],
                'outcome' => $result['outcomeText'],
            ], $this->response->type());
        }
        $this->render('ajax/executeWorkflow');
    }

    public function triggers()
    {
        $triggers = $this->Workflow->getModulesByType('trigger');
        $triggers = $this->Workflow->attachWorkflowToTriggers($triggers);
        $scopes = array_unique(Hash::extract($triggers, '{n}.scope'));
        sort($scopes);
        $filters = $this->IndexFilter->harvestParameters(['scope', 'enabled', 'blocking']);
        if (!empty($filters['scope'])) {
            $triggers = array_filter($triggers, function($trigger) use ($filters) {
                return $trigger['scope'] === $filters['scope'];
            });
        }
        if (isset($filters['enabled'])) {
            $triggers = array_filter($triggers, function($trigger) use ($filters) {
                return $trigger['disabled'] != $filters['enabled'];
            });
        }
        if (isset($filters['blocking'])) {
            $triggers = array_filter($triggers, function($trigger) use ($filters) {
                return $trigger['blocking'] == $filters['blocking'];
            });
        }
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $customPagination->truncateAndPaginate($triggers, $this->params, 'Workflow', true);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($triggers, $this->response->type());
        }

        $this->set('data', $triggers);
        $this->set('scopes', $scopes);
        $this->set('filters', $filters);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'index_trigger']);
    }

    public function moduleIndex()
    {
        $modules = $this->Workflow->getModulesByType();
        $errorWhileLoading = $this->Workflow->getModuleLoadingError();
        $this->Module = ClassRegistry::init('Module');
        $mispModules = $this->Module->getModules('Action');
        $this->set('module_service_error', !is_array($mispModules));
        $filters = $this->IndexFilter->harvestParameters(['type', 'actiontype', 'enabled']);
        $moduleType = $filters['type'] ?? 'action';
        $actionType = $filters['actiontype'] ?? 'all';
        $enabledState = $filters['enabled'] ?? false;
        if ($moduleType == 'all' || $moduleType == 'custom') {
            $data = array_merge(
                $modules["modules_action"],
                $modules["modules_logic"]
            );
        } else {
            $data = $modules["modules_{$moduleType}"];
        }
        if ($actionType == 'mispmodule') {
            $data = array_filter($data, function($module) {
                return !empty($module['is_misp_module']);
            });
        } else if ($actionType == 'blocking') {
            $data = array_filter($data, function ($module) {
                return !empty($module['blocking']);
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
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $params = $customPagination->createPaginationRules($data, $this->passedArgs, 'Workflow');
        $params = $customPagination->applyRulesOnArray($data, $params, 'Workflow');
        $params['options'] = array_merge($params['options'], $filters);
        $this->params['paging'] = [$this->modelClass => $params];
        $this->set('data', $data);
        $this->set('indexType', $moduleType);
        $this->set('actionType', $actionType);
        $this->set('errorWhileLoading', $errorWhileLoading);
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
        if (!isset($module['Workflow']))
            $module['Workflow'] = ['counter' => false, 'id' => false];
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

    public function debugToggleField($workflow_id, $enabled)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This action is available via AJAX only.'));
        }
        $this->layout = false;
        $this->render('ajax/getDebugToggleField');
        if ($this->request->is('post') || $this->request->is('put')) {
            $success = $this->Workflow->toggleDebug($workflow_id, $enabled);
            if (!empty($success)) {
                return $this->__getSuccessResponseBasedOnContext(
                    __('%s debug mode', ($enabled ? __('Enabled') : __('Disabled'))),
                    null,
                    'toggle_debug',
                    $workflow_id,
                    ['action' => 'triggers']
                );
            } else {
                return $this->__getFailResponseBasedOnContext(
                    __('Could not %s debug mode', ($enabled ? __('enable') : __('disable'))),
                    null,
                    'toggle_debug',
                    $workflow_id,
                    ['action' => 'triggers']
                );
            }
        }
    }

    public function massToggleField($fieldName, $enabled, $is_trigger=false)
    {
        if (!in_array($fieldName, $this->toggleableFields)) {
            throw new MethodNotAllowedException(__('The field `%s` cannot be toggled', $fieldName));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $module_ids = JsonTool::decode($this->request->data['Workflow']['module_ids']);
            $enabled_count = $this->Workflow->toggleModules($module_ids, $enabled, $is_trigger);
            if (!empty($enabled_count)) {
                return $this->__getSuccessResponseBasedOnContext(
                    __('%s %s modules', ($enabled ? 'Enabled' : 'Disabled'), $enabled_count),
                    null,
                    'toggle_module',
                    $module_ids,
                    ['action' => (!empty($is_trigger) ? 'triggers' : 'moduleIndex')]
                );
            } else {
                return $this->__getFailResponseBasedOnContext(
                    __('Could not %s modules', ($enabled ? 'enable' : 'disable')),
                    null,
                    'toggle_module',
                    $module_ids,
                    ['action' => (!empty($is_trigger) ? 'triggers' : 'moduleIndex')]
                );
            }
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
        if (!isset($newWorkflow['Workflow'])) {
            $newWorkflow = ['Workflow' => $newWorkflow];
        }
        $ignoreFieldList = ['id', 'uuid'];
        foreach (Workflow::CAPTURE_FIELDS_EDIT as $field) {
            if (!in_array($field, $ignoreFieldList) && isset($newWorkflow['Workflow'][$field])) {
                $savedWorkflow['Workflow'][$field] = $newWorkflow['Workflow'][$field];
            }
        }
        return $savedWorkflow;
    }

    public function checkGraph()
    {
        $this->request->allowMethod(['post']);
        $graphData = JsonTool::decode($this->request->data['graph']);
        $cycles = [];
        $isAcyclic = $this->Workflow->workflowGraphTool->isAcyclic($graphData, $cycles);
        $edgesMultipleOutput = [];
        $hasMultipleOutputConnection = $this->Workflow->workflowGraphTool->hasMultipleOutputConnection($graphData, $edgesMultipleOutput);
        $edgesWarnings = [];
        $hasPathWarnings = $this->Workflow->hasPathWarnings($graphData, $edgesWarnings);
        $data = [
            'is_acyclic' => [
                'is_acyclic' => $isAcyclic,
                'cycles' => $cycles,
            ],
            'multiple_output_connection' => [
                'has_multiple_output_connection' => $hasMultipleOutputConnection,
                'edges' => $edgesMultipleOutput,
            ],
            'path_warnings' => [
                'has_path_warnings' => $hasPathWarnings,
                'edges' => $edgesWarnings,
            ],
        ];
        return $this->RestResponse->viewData($data, 'json');
    }

    public function moduleStatelessExecution($module_id)
    {
        $this->request->allowMethod(['post']);
        $input_data = JsonTool::decode($this->request->data['input_data']);
        $param_data = $this->request->data['module_indexed_param'];
        $convert_data = $this->request->data['convert_data'];
        $result = $this->Workflow->moduleStatelessExecution($module_id, $input_data, $param_data, $convert_data);
        return $this->RestResponse->viewData($result, 'json');
    }
}
