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
        }
        if (empty(Configure::read('Plugin.Workflow_enable'))) {
            $requirementErrors[] = __('The workflow plugin must be enabled to use workflows. Go to `/servers/serverSettings/Plugin` and enable the `Plugin.Workflow` setting');
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
        if ($this->theme === 'Overmind') {
            if (!empty($this->viewVars['requirementErrors'])) {
                return $this->render('error');
            }
            $this->__setHubStats();
        }
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'index'));
    }

    /**
     * __setHubStats Collect the counters powering the Overmind workflow hub.
     *
     */
    private function __setHubStats()
    {
        $countEnabled = function (array $items) {
            return count(array_filter($items, function ($item) {
                return empty($item['disabled']);
            }));
        };

        $modules = $this->Workflow->getModulesByType();
        $coreTriggers = $this->Workflow->attachWorkflowToTriggers(array_values(array_filter(
            $modules['modules_trigger'],
            function ($trigger) {
                return empty($trigger['is_adhoc']);
            }
        )));
        $adhocTriggers = array_values(array_filter($modules['modules_trigger'], function ($trigger) {
            return !empty($trigger['is_adhoc']);
        }));

        $this->set('hubTriggers', [
            'total' => count($coreTriggers),
            'enabled' => $countEnabled($coreTriggers),
            'attached' => count(array_filter($coreTriggers, function ($trigger) {
                return !empty($trigger['Workflow']);
            })),
            'blocking' => count(array_filter($coreTriggers, function ($trigger) {
                return !empty($trigger['blocking']);
            })),
            'scopes' => count(array_unique(Hash::extract($coreTriggers, '{n}.scope'))),
        ]);
        $this->set('hubAdhoc', [
            'total' => count($adhocTriggers),
            'enabled' => $countEnabled($adhocTriggers),
        ]);

        $actionModules = $modules['modules_action'];
        $logicModules = $modules['modules_logic'];
        $allModules = array_merge($actionModules, $logicModules);
        $this->Module = ClassRegistry::init('Module');
        $this->set('hubModules', [
            'total' => count($allModules),
            'enabled' => $countEnabled($allModules),
            'action' => count($actionModules),
            'logic' => count($logicModules),
            'misp_module' => count(array_filter($actionModules, function ($module) {
                return !empty($module['is_misp_module']);
            })),
            'custom' => count(array_filter($allModules, function ($module) {
                return !empty($module['is_custom']);
            })),
            'service_error' => !is_array($this->Module->getModules('Action')),
            'loading_errors' => count($this->Workflow->getModuleLoadingError()),
        ]);

        $this->loadModel('WorkflowBlueprint');
        $blueprints = $this->WorkflowBlueprint->find('first', [
            'recursive' => -1,
            'fields' => [
                'COUNT(*) AS total',
                'SUM(WorkflowBlueprint.default) AS shipped',
            ],
            'callbacks' => false,
        ]);
        $this->set('hubBlueprints', [
            'total' => (int)($blueprints[0]['total'] ?? 0),
            'default' => (int)($blueprints[0]['shipped'] ?? 0),
        ]);

        $totals = $this->Workflow->find('first', [
            'recursive' => -1,
            'fields' => [
                'COUNT(*) AS total',
                'SUM(Workflow.counter) AS runs',
                'SUM(Workflow.debug_enabled) AS debugging',
            ],
            'callbacks' => false,
        ]);
        $this->set('hubWorkflows', [
            'total' => (int)($totals[0]['total'] ?? 0),
            'runs' => (int)($totals[0]['runs'] ?? 0),
            'debugging' => (int)($totals[0]['debugging'] ?? 0),
        ]);
    }

    public function rebuildRedis()
    {
        $this->Workflow->rebuildRedis();
    }

    public function add()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $newWorkflow = $this->request->data;
            $newWorkflow['Workflow']['data'] = empty($newWorkflow['Workflow']['data']) ? [] : JsonTool::decode($newWorkflow['Workflow']['data']);
            if (empty($newWorkflow['Workflow']['data'])) {
                $trigger_id = $this->Workflow->genAdHocTriggerID();
                $newWorkflow['Workflow']['trigger_id'] = $trigger_id;
                $newWorkflow['Workflow']['data'] = $this->Workflow->genGraphDataForTrigger($trigger_id);
            }
            $result = $this->Workflow->addWorkflow($newWorkflow);
            if (!empty($result['errors'])) {
                $redirectTarget = null;
                return $this->__getFailResponseBasedOnContext($result['errors'], null, 'edit', $this->Workflow->id, $redirectTarget);
            } else {
                /*
                 * A workflow added from the UI carries no graph, so addWorkflow()
                 * gave it a generated ad-hoc trigger. Send the user back to the
                 * ad-hoc index they came from rather than to the legacy view.
                 */
                $redirectTarget = $this->theme === 'Overmind'
                    ? ['action' => 'adhoc']
                    : ['action' => 'view', $result['saved']['Workflow']['id']];
                $successMessage = __('Workflow saved.');
                $savedWorkflow = $result['saved'];
                $savedWorkflow = $this->Workflow->attachLabelToConnections($savedWorkflow);
                return $this->__getSuccessResponseBasedOnContext($successMessage, $savedWorkflow, 'edit', false, $redirectTarget);
            }
        }

        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'add']);
        if ($this->theme === 'Overmind') {
            $this->layout = false;
        }
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
            $redirectTarget = $this->theme === 'Overmind'
                ? $this->referer(['action' => 'index'])
                : ['action' => 'view', $id];
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
        if ($this->theme === 'Overmind') {
            $this->layout = false;
        }
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

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'Workflow',
            'restName' => 'Workflows',
            'itemName' => 'workflow',
            'view' => 'ajax/workflowDeleteConfirmationForm',
            'checkModifyCallback' => function () {
                return $this->userRole['perm_site_admin'];
            },
            'multiSuccessMessageCallback' => function ($count) {
                return __n('%s workflow deleted.', '%s workflows deleted.', $count, $count);
            }
        ]);
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
                    [__('Unknown trigger %s', $trigger_id)],
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
        // Override description placeholder with the workflow's name
        foreach ($modules['modules_trigger'] as $i => $trigger) {
            if ($trigger['id'] == $workflow['Workflow']['trigger_id']) {
                $modules['modules_trigger'][$i]['description'] = sprintf('%s - %s', $workflow['Workflow']['name'], $workflow['Workflow']['description']);
                break;
            }
        }
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
            if (empty($this->request->data['Workflow']['data'])) {
                $this->request->data['Workflow']['data'] = '[]';
            }
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
            if ($this->_isRest() || $this->request->is('ajax')) {
                return $this->RestResponse->viewData([
                    'success' => $result['success'],
                    'outcome' => $result['outcomeText'],
                ], $this->response->type());
            } else {
                if (empty($result['success'])) {
                    $this->Flash->error($result['outcomeText']);
                } else {
                    $this->Flash->success('Workflow successfully executed.');
                }
                // 'scope' was never a routing key: it leaked through as a named
                // param, landing the user on /workflows/adhoc/scope:workflows.
                $this->redirect(['action' => 'adhoc']);
            }
        }
        $this->render('ajax/executeWorkflow');
    }


    public function adhoc()
    {
        $triggers = $this->Workflow->getModulesByType('trigger');
        $triggers = array_filter($triggers, function($trigger) {
            return !empty($trigger['is_adhoc']);
        });
        $triggers = $this->Workflow->attachWorkflowToTriggers($triggers);
        $triggers = $this->Workflow->attachTriggerParamsToWorkflow($triggers);

        /*
         * Data input scopes are read off the trigger node of each graph, so the
         * list is only as complete as the workflows that have been configured —
         * collect it before filtering so the dropdown does not shrink as the
         * user narrows the index down.
         */
        $dataInputScopes = array_values(array_filter(array_unique(
            Hash::extract(array_values($triggers), '{n}.trigger_scope')
        )));
        sort($dataInputScopes);

        $filters = $this->IndexFilter->harvestParameters(['enabled', 'trigger_scope', 'quickFilter']);
        if (!empty($filters['quickFilter'])) {
            $needle = mb_strtolower($filters['quickFilter']);
            $triggers = array_filter($triggers, function ($trigger) use ($needle) {
                return mb_strpos(mb_strtolower((string)Hash::get($trigger, 'Workflow.name')), $needle) !== false;
            });
        }
        if (isset($filters['enabled']) && $filters['enabled'] !== '') {
            $wantEnabled = !empty($filters['enabled']);
            $triggers = array_filter($triggers, function ($trigger) use ($wantEnabled) {
                return empty($trigger['disabled']) === $wantEnabled;
            });
        }
        if (!empty($filters['trigger_scope'])) {
            $triggers = array_filter($triggers, function ($trigger) use ($filters) {
                return (string)Hash::get($trigger, 'trigger_scope') === $filters['trigger_scope'];
            });
        }

        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $customPagination->truncateAndPaginate($triggers, $this->params, 'Workflow', true);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($triggers, $this->response->type());
        }

        if ($this->theme === 'Overmind') {
            foreach ($triggers as $i => $trigger) {
                $triggers[$i]['enabled'] = empty($trigger['disabled']);
            }
        }

        $this->set('data', $triggers);
        $this->set('dataInputScopes', $dataInputScopes);
        $this->set('filters', $filters);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'index_adhoc']);
    }

    public function triggers()
    {
        $triggers = $this->Workflow->getModulesByType('trigger');
        $triggers = $this->Workflow->attachWorkflowToTriggers($triggers);
        $triggers = array_filter($triggers, function($trigger) {
            return empty($trigger['is_adhoc']);
        });
        // Scopes are collected after the ad-hoc triggers are dropped: 'adhoc' is
        // never reachable here, so offering it as a filter yields an empty page.
        $scopes = array_unique(Hash::extract(array_values($triggers), '{n}.scope'));
        sort($scopes);
        $filters = $this->IndexFilter->harvestParameters(['scope', 'enabled', 'blocking', 'quickFilter']);
        if (!empty($filters['quickFilter'])) {
            $needle = mb_strtolower($filters['quickFilter']);
            $triggers = array_filter($triggers, function ($trigger) use ($needle) {
                return mb_strpos(mb_strtolower($trigger['name']), $needle) !== false;
            });
        }
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

        if ($this->theme === 'Overmind') {
            foreach ($triggers as $i => $trigger) {
                $triggers[$i]['enabled'] = empty($trigger['disabled']);
            }
        }

        $this->set('data', $triggers);
        $this->set('scopes', $scopes);
        $this->set('filters', $filters);
        $this->set('menuData', ['menuList' => 'workflows', 'menuItem' => 'index_trigger']);
    }

    /**
     * massToggleTrigger Enable or disable several triggers at once.
     *
     * @param string $enabled target state, '1' or '0'
     * @param string $idList JSON array of trigger ids
     */
    public function massToggleTrigger($enabled, $idList = null)
    {
        return $this->__massToggle($enabled, $idList, true);
    }

    /**
     * massToggleModule Enable or disable several action/logic modules at once.
     *
     * @param string $enabled target state, '1' or '0'
     * @param string $idList JSON array of module ids
     */
    public function massToggleModule($enabled, $idList = null)
    {
        return $this->__massToggle($enabled, $idList, false);
    }

    /**
     * __massToggle Shared body of the two mass-toggle endpoints.
     *
     *
     * @param string $enabled target state, '1' or '0'
     * @param string $idList JSON array of ids
     * @param bool $isTrigger toggling triggers rather than action/logic modules
     */
    private function __massToggle($enabled, $idList, $isTrigger)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException(__('Insufficient privileges'));
        }
        $enabled = !empty($enabled) && $enabled !== '0';
        $cleanIdList = htmlspecialchars_decode(urldecode((string)$idList));
        $ids = json_decode($cleanIdList, true);
        if (empty($ids) || !is_array($ids)) {
            throw new NotFoundException(__('Invalid IDs provided.'));
        }

        if ($isTrigger) {
            $redirectAction = $this->Workflow->isAdHocTrigger($ids[0]) ? 'adhoc' : 'triggers';
        } else {
            $redirectAction = 'moduleIndex';
        }

        if ($this->request->is(['post', 'put'])) {
            $count = $this->Workflow->toggleModules($ids, $enabled, $isTrigger);
            $verb = $enabled ? __('enabled') : __('disabled');
            $message = $isTrigger
                ? __n('%s trigger %s.', '%s triggers %s.', $count, $count, $verb)
                : __n('%s module %s.', '%s modules %s.', $count, $count, $verb);
            return $this->__getSuccessResponseBasedOnContext(
                $message,
                null,
                'toggle_module',
                false,
                ['action' => $redirectAction]
            );
        }

        $endpoint = $isTrigger ? 'massToggleTrigger' : 'massToggleModule';
        $this->layout = false;
        $this->set('actionText', $enabled ? __('enable') : __('disable'));
        $this->set('itemLabel', $isTrigger ? __('trigger') : __('module'));
        $this->set('itemLabelPlural', $isTrigger ? __('triggers') : __('modules'));
        $this->set('idArray', $ids);
        $this->set('url', '/workflows/' . $endpoint . '/' . ($enabled ? '1' : '0') . '/' . urlencode($cleanIdList));
        $this->render('ajax/massToggleConfirmationForm');
    }

    public function moduleIndex()
    {
        $modules = $this->Workflow->getModulesByType();
        $errorWhileLoading = $this->Workflow->getModuleLoadingError();
        $this->Module = ClassRegistry::init('Module');
        $mispModules = $this->Module->getModules('Action');
        $this->set('module_service_error', !is_array($mispModules));
        $filters = $this->IndexFilter->harvestParameters(['type', 'actiontype', 'enabled', 'quickFilter']);
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
        // Searchbar for Overmind index
        if (!empty($filters['quickFilter'])) {
            $needle = mb_strtolower($filters['quickFilter']);
            $data = array_filter($data, function ($module) use ($needle) {
                return mb_strpos(mb_strtolower((string)$module['name']), $needle) !== false;
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
        if ($this->theme === 'Overmind') {
            foreach ($data as $i => $module) {
                $data[$i]['enabled'] = empty($module['disabled']);
            }
        }
        $this->set('data', $data);
        $this->set('filters', $filters);
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
        $is_adhoc_workflow = $this->Workflow->isAdHocTrigger($module_id);
        if ($saved) {
            return $this->__getSuccessResponseBasedOnContext(
                __('%s module %s', ($enabled ? 'Enabled' : 'Disabled'), $module_id),
                null,
                'toggle_module',
                $module_id,
                ['action' => (!empty($is_trigger) ? ($is_adhoc_workflow ? 'adhoc' : 'triggers') : 'moduleIndex')]
            );
        } else {
            return $this->__getFailResponseBasedOnContext(
                __('Could not %s module %s', ($enabled ? 'Enabled' : 'Disabled'), $module_id),
                null,
                'toggle_module',
                $module_id,
                ['action' => (!empty($is_trigger) ? ($is_adhoc_workflow ? 'adhoc' : 'triggers') : 'moduleIndex')]
            );
        }
    }

    /**
     * toggleDebugMode Turn a workflow's debug mode on or off.
     *
     *
     * @param int $workflow_id
     * @param string $enabled target state, '1' or '0'
     */
    public function toggleDebugMode($workflow_id, $enabled)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException(__('Insufficient privileges'));
        }
        $workflow = $this->Workflow->fetchWorkflow($workflow_id);
        if (empty($workflow)) {
            throw new NotFoundException(__('Invalid workflow'));
        }
        $enabled = !empty($enabled) && $enabled !== '0';
        $redirect = ['action' => $this->Workflow->isAdHocTrigger($workflow['Workflow']['trigger_id']) ? 'adhoc' : 'triggers'];

        if ($this->request->is(['post', 'put'])) {
            $saved = $this->Workflow->toggleDebug($workflow_id, $enabled);
            if ($saved) {
                return $this->__getSuccessResponseBasedOnContext(
                    __('%s debug mode for workflow #%s.', $enabled ? __('Enabled') : __('Disabled'), $workflow_id),
                    null,
                    'toggle_debug',
                    $workflow_id,
                    $redirect
                );
            }
            return $this->__getFailResponseBasedOnContext(
                __('Could not %s debug mode.', $enabled ? __('enable') : __('disable')),
                null,
                'toggle_debug',
                $workflow_id,
                $redirect
            );
        }

        $this->layout = false;
        $this->set('actionText', $enabled ? __('enable') : __('disable'));
        $this->set('workflow', $workflow);
        $this->set('url', '/workflows/toggleDebugMode/' . $workflow_id . '/' . ($enabled ? '1' : '0'));
        $this->render('ajax/debugToggleConfirmationForm');
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
