<?php
App::uses('AppModel', 'Model');
App::uses('WorkflowGraphTool', 'Tools');
App::uses('Folder', 'Utility');

class WorkflowDuplicatedModuleIDException extends Exception {}
class TriggerNotFoundException extends Exception {}
class ModuleNotFoundException extends Exception {}
class WorkflowNotFoundException extends Exception {}

class Workflow extends AppModel
{
    public $recursive = -1;

    public $actsAs = [
        // 'AuditLog',
        'Containable',
        'SysLogLogable.SysLogLogable' => [
            'roleModel' => 'Role',
            'roleKey' => 'role_id',
            'change' => 'full'
        ],
    ];

    public $belongsTo = [
    ];

    public $validate = [
        'value' => [
            'stringNotEmpty' => [
                'rule' => ['stringNotEmpty']
            ]
        ],
        'uuid' => [
            'uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ],
            'unique' => [
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'required' => 'create'
            ]
        ],
        'data' => [
            'hasAcyclicGraph' => [
                'rule' => ['hasAcyclicGraph'],
                'message' => 'Cannot save a workflow containing a cycle',
            ],
            'hasOneTrigger' => [
                'rule' => ['hasOneTrigger'],
                'message' => 'Cannot save a workflow containing no or more than one trigger',
            ],
            'satisfiesMultipleConnectionCondition' => [
                'rule' => ['satisfiesMultipleConnectionCondition'],
                'message' => 'Cannot save a workflow having more than one connection per output',
            ]
        ]
    ];

    /** @var WorkflowGraphTool */
    public $workflowGraphTool;
    public $defaultContain = [
    ];

    private $loaded_modules = [];
    private $loaded_classes = [];
    private $error_while_loading = [];

    private $module_initialized = false;
    private $modules_enabled_by_default = ['generic-if', 'distribution-if', 'published-if', 'organisation-if', 'tag-if', 'concurrent-task', 'stop-execution', 'webhook', 'push-zmq'];

    const CAPTURE_FIELDS_EDIT = ['name', 'description', 'timestamp', 'data', 'debug_enabled'];
    const CAPTURE_FIELDS_ADD = ['uuid', 'name', 'description', 'timestamp', 'data', 'trigger_id', 'debug_enabled'];

    const MODULE_ROOT_PATH = APP . 'Model/WorkflowModules/';
    const CUSTOM_MODULE_ROOT_PATH = APP . 'Lib/WorkflowModules/';
    const REDIS_KEY_WORKFLOW_NAMESPACE = 'workflow';
    const REDIS_KEY_WORKFLOW_PER_TRIGGER = 'workflow:workflow_list:%s';
    const REDIS_KEY_TRIGGER_PER_WORKFLOW = 'workflow:trigger_list:%s';
    const REDIS_KEY_MODULES_ENABLED = 'workflow:modules_enabled';

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->workflowGraphTool = new WorkflowGraphTool();
    }

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['Workflow']['uuid'])) {
            $this->data['Workflow']['uuid'] = CakeText::uuid();
        } else {
            $this->data['Workflow']['uuid'] = strtolower($this->data['Workflow']['uuid']);
        }
        if (empty($this->data['Workflow']['data'])) {
            $this->data['Workflow']['data'] = [];
        }
        if (empty($this->data['Workflow']['timestamp'])) {
            $this->data['Workflow']['timestamp'] = time();
        }
        if (empty($this->data['Workflow']['description'])) {
            $this->data['Workflow']['description'] = '';
        }
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (empty($result['Workflow']['data'])) {
                $result['Workflow']['data'] = '{}';
            }
            $results[$k]['Workflow']['data'] = JsonTool::decode($result['Workflow']['data']);
            if (!empty($result['Workflow']['id'])) {
                $trigger_ids = $this->__getTriggersIDPerWorkflow((int) $result['Workflow']['id']);
                $results[$k]['Workflow']['listening_triggers'] = $this->getModuleByID($trigger_ids);
            }
        }
        return $results;
    }

    public function beforeSave($options = [])
    {
        if (is_array($this->data['Workflow']['data'])) {
            $this->data['Workflow']['data'] = JsonTool::encode($this->data['Workflow']['data']);
        }
        return true;
    }

    public function afterSave($created, $options = [])
    {
        $this->updateListeningTriggers($this->data);
    }

    public function beforeDelete($cascade = true)
    {
        parent::beforeDelete($cascade);
        $workflow = $this->find('first', [ // $this->data is empty in afterDelete?!
            'recursive' => -1,
            'conditions' => ['Workflow.id' => $this->id]
        ]);
        $workflow['Workflow']['data'] = []; // Make sure not trigger are listening
        $this->workflowToDelete = $workflow;
    }

    public function afterDelete()
    {
        // $this->data is empty?!
        parent::afterDelete();
        $this->updateListeningTriggers($this->workflowToDelete);
    }

    public function enableDefaultModules()
    {
        $this->toggleModules($this->modules_enabled_by_default, true, false);
    }

    /**
     * @param string $trigger_id
     * @return bool
     * @throws WorkflowDuplicatedModuleIDException
     */
    protected function checkTriggerEnabled($trigger_id)
    {
        static $enabled;

        if ($enabled === null) {
            $enabled = (bool)Configure::read('Plugin.Workflow_enable');
        }
        if (!$enabled) {
            return false;
        }

        $settingName = "Plugin.Workflow_triggers_$trigger_id";
        $module_disabled = empty(Configure::read($settingName));
        if ($module_disabled) {
            return false;
        }

        $filename = sprintf('Module_%s.php', preg_replace('/[^a-zA-Z0-9_]/', '_', Inflector::underscore($trigger_id)));
        $module_config = $this->__getClassFromModuleFiles('trigger', [$filename], false)['classConfigs'];
        return empty($module_config['disabled']);
    }

    protected function getEnabledModules(): array
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        $list = $redis->sMembers(Workflow::REDIS_KEY_MODULES_ENABLED);
        return !empty($list) ? $list : [];
    }

    public function toggleModule($module_id, $enable, $is_trigger=false): bool
    {
        if (!empty($is_trigger)) {
            $settingName = sprintf('Plugin.Workflow_triggers_%s', $module_id);
            $server = ClassRegistry::init('Server');
            return $server->serverSettingsSaveValue($settingName, !empty($enable), false);
        } else {
            try {
                $redis = $this->setupRedisWithException();
            } catch (Exception $e) {
                return false;
            }
            if ($enable) {
                $redis->sAdd(Workflow::REDIS_KEY_MODULES_ENABLED, $module_id);
            } else {
                $redis->sRem(Workflow::REDIS_KEY_MODULES_ENABLED, $module_id);
            }
        }
        return true;
    }

    public function toggleDebug($workflow_id, $enable): bool
    {
        $workflow = $this->fetchWorkflow($workflow_id);
        $workflow['Workflow']['debug_enabled'] = !empty($enable);
        $result = $this->editWorkflow($workflow);
        return empty($result['errrors']);
    }

    public function toggleModules($module_ids, $enable, $is_trigger=false): int
    {
        $enabled_count = 0;
        foreach ($module_ids as $module_id) {
            $enabled_count += $this->toggleModule($module_id, $enable, $is_trigger) ? 1 : 0;
        }
        return $enabled_count;
    }

    protected function checkTriggerListenedTo($trigger_id)
    {
        return !empty($this->__getWorkflowsIDPerTrigger($trigger_id));
    }

    public function rebuildRedis()
    {
        $redis = $this->setupRedisWithException();
        $workflows = $this->fetchWorkflows();
        $keys = $redis->keys(Workflow::REDIS_KEY_WORKFLOW_NAMESPACE . ':*');
        $redis->delete($keys);
        foreach ($workflows as $wokflow) {
            $this->updateListeningTriggers($wokflow);
        }
    }

    /**
     * updateListeningTriggers 
     *  - Update the list of triggers that will be run this workflow
     *  - Update the list of workflows that are run by their triggers
     *  - Update the ordered list of workflows that are run by their triggers
     *
     * @param  array $workflow
     */
    public function updateListeningTriggers($workflow)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            $this->logException('Failed to setup redis ', $e);
            return false;
        }
        if (!is_array($workflow['Workflow']['data'])) {
            $workflow['Workflow']['data'] = JsonTool::decode($workflow['Workflow']['data']);
        }
        $original_trigger_list_id = $this->__getTriggersIDPerWorkflow((int)$workflow['Workflow']['id']);
        $new_node_trigger_list = $this->workflowGraphTool->extractTriggersFromWorkflow($workflow['Workflow']['data'], true);
        $new_node_trigger_list_per_id = Hash::combine($new_node_trigger_list, '{n}.data.id', '{n}');
        $new_trigger_list_id = array_keys($new_node_trigger_list_per_id);
        $trigger_to_remove = array_diff($original_trigger_list_id, $new_trigger_list_id);
        $trigger_to_add = array_diff($new_trigger_list_id, $original_trigger_list_id);
        if (!empty($trigger_to_remove)) {
            $pipeline = $redis->multi();
            foreach ($trigger_to_remove as $trigger_id) {
                $pipeline->sRem(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_id), $workflow['Workflow']['id']);
                $pipeline->sRem(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow['Workflow']['id']), $trigger_id);
            }
            $pipeline->exec();
        }
        if (!empty($trigger_to_add)) {
            $pipeline = $redis->multi();
            foreach ($trigger_to_add as $trigger_id) {
                $pipeline->sAdd(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_id), $workflow['Workflow']['id']);
                $pipeline->sAdd(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow['Workflow']['id']), $trigger_id);
            }
            $pipeline->exec();
        }
    }

    /**
     * __getWorkflowsIDPerTrigger Get list of workflow IDs listening to the specified trigger
     *
     * @param  string $trigger_id
     * @return bool|array
     */
    private function __getWorkflowsIDPerTrigger($trigger_id): array
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        $list = $redis->sMembers(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_id));
        return !empty($list) ? $list : [];
    }

    /**
     * __getTriggersIDPerWorkflow Get list of trigger name running to the specified workflow
     *
     * @param  int $workflow_id
     * @return bool|array
     */
    private function __getTriggersIDPerWorkflow(int $workflow_id)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        return $redis->sMembers(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow_id));
    }

    public function getListeningWorkflowForTrigger(array $trigger): array
    {
        return array_map(function($id) {
            return intval($id);
        }, $this->__getWorkflowsIDPerTrigger($trigger['id']));
    }

    /**
     * attachWorkflowToTriggers Collect the workflows listening to this trigger
     *
     * @param  array $triggers
     * @return array
     */
    public function attachWorkflowToTriggers(array $triggers): array
    {
        $workflows = $this->fetchWorkflows([
            'conditions' => [
                'Workflow.trigger_id' => Hash::extract($triggers, '{n}.id'),
            ],
            'fields' => ['*'],
        ]);
        $workflows_per_trigger = Hash::combine($workflows, '{n}.Workflow.trigger_id', '{n}');
        foreach ($triggers as $i => $trigger) {
            if (!empty($workflows_per_trigger[$trigger['id']])) {
                $triggers[$i]['Workflow'] = $workflows_per_trigger[$trigger['id']]['Workflow'];
            }
        }
        return $triggers;
    }

    /**
     * hasAcyclicGraph Return if the graph is acyclic or not
     *
     * @param array $graphData
     * @return boolean
     */
    public function hasAcyclicGraph(array $workflow): bool
    {
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        $isAcyclic = $this->workflowGraphTool->isAcyclic($graphData);
        return $isAcyclic;
    }

    /**
     * hasOneTrigger Return if the graph contain more than one instance of the same trigger
     *
     * @param array $graphData
     * @return boolean
     */
    public function hasOneTrigger(array $workflow): bool
    {
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        $triggers = $this->workflowGraphTool->extractTriggersFromWorkflow($graphData, true);
        return count($triggers) == 1;
    }

    /**
     * satisfiesMultipleConnectionCondition Return if the graph contain more than one instance of the same trigger
     *
     * @param array $graphData
     * @return boolean
     */
    public function satisfiesMultipleConnectionCondition(array $workflow): bool
    {
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        $hasMultipleOutputConnection = $this->workflowGraphTool->hasMultipleOutputConnection($graphData);
        return !$hasMultipleOutputConnection;
    }

    /**
     * executeWorkflow
     *
     * @param int $workflow_id
     * @param array $data
     * @param array $blockingErrors
     * @return array
     */
    public function executeWorkflow($workflow_id, array $data, array &$blockingErrors=[]): array
    {
        $this->loadAllWorkflowModules();

        $workflow = $this->fetchWorkflow($workflow_id, true);
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        $startNode = $this->workflowGraphTool->extractTriggerFromWorkflow($graphData, true);
        $startNodeID = $startNode['id'];
        $trigger_id = $startNode['data']['id'];
        if ($startNode  == -1) {
            $blockingErrors[] = __('Invalid start node `%s`', $startNodeID);
            return false;
        }

        $triggerModule = $this->getModuleClassByType('trigger', $trigger_id, true);
        if (!empty($triggerModule->disabled)) {
            return true;
        }
        $result = $this->__runWorkflow($workflow, $triggerModule, $data, $startNodeID, $blockingErrors);
        return $result;
    }

    /**
     * executeWorkflowForTrigger
     *
     * @param string $trigger_id
     * @param array $data
     * @return bool
     * @throws TriggerNotFoundException
     */
    public function executeWorkflowForTriggerRouter($trigger_id, array $data, array &$blockingErrors=[], array $logging=[]): bool
    {
        $this->loadAllWorkflowModules();

        if (empty($this->loaded_modules['trigger'][$trigger_id])) {
            throw new TriggerNotFoundException(__('Unknown trigger `%s`', $trigger_id));
        }
        $trigger = $this->loaded_modules['trigger'][$trigger_id];
        if (!empty($trigger['disabled'])) {
            return true;
        }

        if (empty($trigger['blocking'])) {
            $this->Job = ClassRegistry::init('Job');
            $jobId = $this->Job->createJob(
                'SYSTEM',
                Job::WORKER_PRIO,
                'executeWorkflowForTrigger',
                sprintf('Workflow for trigger `%s`', $trigger_id),
                __('Executing non-blocking workflow for trigger `%s`', $trigger_id)
            );
            $this->Job->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_WORKFLOW,
                [
                    'executeWorkflowForTrigger',
                    $trigger_id,
                    JsonTool::encode($data),
                    JsonTool::encode($logging),
                    $jobId,
                    Configure::check('CurrentUserId') ? JsonTool::encode(Configure::read('CurrentUserId')) : null,
                ],
                true,
                $jobId
            );
            return true;
        } else {
            $blockingPathExecutionSuccess = $this->executeWorkflowForTrigger($trigger_id, $data, $blockingErrors);
            return $blockingPathExecutionSuccess;
        }
    }

    /**
     * executeWorkflowForTrigger
     *
     * @param string $trigger_id
     * @param array $data
     * @param array $errors
     * @return boolean True if the execution for the blocking path was a success
     * @throws TriggerNotFoundException
     */
    public function executeWorkflowForTrigger($trigger_id, array $data, array &$blockingErrors=[]): bool
    {
        $this->loadAllWorkflowModules();

        $triggerModule = $this->getModuleClassByType('trigger', $trigger_id, true);
        if (!empty($triggerModule->disabled)) {
            return true;
        }

        $workflow = $this->fetchWorkflowByTrigger($trigger_id, true);
        if (empty($workflow)) {
            throw new WorkflowNotFoundException(__('Could not get workflow for trigger `%s`', $trigger_id));
        }
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        $startNodeID = $this->workflowGraphTool->getNodeIdForTrigger($graphData, $trigger_id);
        if ($startNodeID  == -1) {
            $blockingErrors[] = __('Invalid start node `%s`', $startNodeID);
            return false;
        }
        $result = $this->__runWorkflow($workflow, $triggerModule, $data, $startNodeID, $blockingErrors);
        return $result['success'];
    }

    /**
     * runWorkflow
     *
     * @param array $workflow
     * @param $triggerModule
     * @param array $data
     * @param int $startNodeID
     * @return array
     */
    private function __runWorkflow(array $workflow, $triggerModule, array $data, $startNodeID, &$blockingErrors=[]): array
    {
        $this->Log = ClassRegistry::init('Log');
        $message =  __('Started executing workflow for trigger `%s` (%s)', $triggerModule->id, $workflow['Workflow']['id']);
        $this->logExecutionIfDebug($workflow, $message);
        $workflow = $this->__incrementWorkflowExecutionCount($workflow);
        $walkResult = [];
        $debugData = ['original' => $data];
        $conversionFailure = false;
        try {
            $data = $this->__normalizeDataForTrigger($triggerModule, $data);
        } catch (Throwable $e) {
            $conversionFailure = true;
            $message = __('Error while normalizing data for trigger. Error:' . PHP_EOL . $e->getMessage());
        }
        if ($data === false) {
            $conversionFailure = true;
            $message = __('Error while normalizing data for trigger. Invalid input.');
        }
        if ($conversionFailure) {
            $this->logExecutionIfDebug($workflow, $message);
            return [
                'outcomeText' => 'failure' . sprintf(' %s', $message),
                'walkResult' => [],
                'success' => false,
            ];
        }
        $debugData['normalized'] = $data;
        $for_path = !empty($triggerModule->blocking) ? GraphWalker::PATH_TYPE_BLOCKING : GraphWalker::PATH_TYPE_NON_BLOCKING;
        $this->sendRequestToDebugEndpointIfDebug($workflow, [], '/init?type=' . $for_path, $debugData);

        $blockingPathExecutionSuccess = $this->walkGraph($workflow, $startNodeID, $for_path, $data, $blockingErrors, $walkResult);
        $executionStoppedByStopModule = in_array('stop-execution', Hash::extract($walkResult, 'blocking_nodes.{n}.data.id'));
        if (empty($blockingPathExecutionSuccess)) {
            $message = __('Execution stopped. %s', PHP_EOL . implode(', ', $blockingErrors));
            $this->logExecutionError($workflow, $message);
        } else if (!empty($blockingErrors)) {
            $message = __('Execution encountered an error but continued. %s', PHP_EOL . implode(', ', $blockingErrors));
            $this->logExecutionError($workflow, $message);
        }
        $outcomeText = 'failure';
        if (!empty($blockingPathExecutionSuccess)) {
            $outcomeText = 'success';
        } else if ($executionStoppedByStopModule) {
            $outcomeText = 'blocked';
        }
        $message =  __('Finished executing workflow for trigger `%s` (%s). Outcome: %s', $triggerModule->id, $workflow['Workflow']['id'], $outcomeText);

        $this->logExecutionIfDebug($workflow, $message);
        $this->sendRequestToDebugEndpointIfDebug($workflow, [], '/end?outcome=' . $outcomeText, $walkResult);
        return [
            'outcomeText' => $outcomeText,
            'walkResult' => $walkResult,
            'success' => $blockingPathExecutionSuccess,
        ];
    }

    /**
     * walkGraph Walk the graph for the provided trigger and execute each nodes
     *
     * @param array $workflow The worflow to walk
     * @param int $startNode The ID of the trigger to start from
     * @param string|null $for_path If provided, execute the workflow for the provided path. If not provided, execute the worflow regardless of the path
     * @param array $data
     * @param array $errors
     * @return boolean If all module returned a successful response
     */
    public function walkGraph(array $workflow, int $startNode, $for_path=null, array $data=[], array &$errors=[], array &$walkResult=[]): bool
    {
        $walkResult = [
            'blocking_nodes' => [],
            'executed_nodes' => [],
            'blocked_paths' => [],
        ];
        $userForWorkflow = $this->getUserForWorkflow();
        if (empty($userForWorkflow)) {
            $errors[] = __('Could not find a valid user to run the workflow. Please set setting `MISP.host_org_id` or make sure a valid site_admin user exists.');
            return false;
        }
        $roamingData = $this->workflowGraphTool->getRoamingData($userForWorkflow, $data, $workflow, $startNode);
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        $graphWalker = $this->workflowGraphTool->getWalkerIterator($graphData, $this, $startNode, $for_path, $roamingData);
        $preventExecutionForPaths = [];
        foreach ($graphWalker as $graphNode) {
            $node = $graphNode['node'];
            $moduleClass = $this->getModuleClass($node);
            foreach ($preventExecutionForPaths as $path_to_block) {
                if ($path_to_block == array_slice($graphNode['path_list'], 0, count($path_to_block))) {
                    $walkResult['blocked_paths'][] = $graphNode['path_list'];
                    continue 2;
                }
            }
            $nodeError = [];
            $success = $this->executeNode($node, $roamingData, $nodeError);
            $walkResult['executed_nodes'][] = $node;
            if (empty($success)) {
                $walkResult['blocking_nodes'][] = $node;
                if (!empty($nodeError)) {
                    $errors[] = __(
                        'Node `%s` (%s) from Workflow `%s` (%s) returned the following error: %s',
                        $node['data']['id'],
                        $node['id'],
                        $workflow['Workflow']['name'],
                        $workflow['Workflow']['id'],
                        implode(', ', $nodeError)
                    );
                }
                if (!empty($moduleClass->blocking)) {
                    return false; // Node stopped execution for any path. If a module is blocking and it failed, stop the walk
                } else if ($graphNode['path_type'] == GraphWalker::PATH_TYPE_NON_BLOCKING) {
                    $preventExecutionForPaths[] = $graphNode['path_list']; // Paths down the chain should not be executed
                }
            }
        }
        return true;
    }

    public function getUserForWorkflow(): array
    {
        $this->Organisation = ClassRegistry::init('Organisation');
        $hostOrg = $this->Organisation->find('first', [
            'recursive' => -1,
            'conditions' => [
                'id' => Configure::read('MISP.host_org_id')
            ],
        ]);
        $this->User = ClassRegistry::init('User');
        if (!empty($hostOrg)) {
            $perms = array_keys($this->User->Role->permFlags);
            $allPermEnabled = array_map(function($perm) {
                return true;
            }, array_flip($perms));
            $userForWorkflow = [
                'email' => 'SYSTEM',
                'id' => 0,
                'org_id' => $hostOrg['Organisation']['id'],
                'Role' => $allPermEnabled,
                'Organisation' => $hostOrg['Organisation']
            ];
        } else {
            $userForWorkflow = $this->User->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'Role.perm_site_admin' => 1,
                    'User.disabled' => 0
                ],
                'contain' => [
                    'Organisation' => ['fields' => ['name']],
                    'Role' => ['fields' => ['*']],
                ],
                'fields' => ['User.org_id', 'User.id', 'User.email'],
            ]);
            $userForWorkflow['Server'] = [];
            $userForWorkflow = $this->User->rearrangeToAuthForm($userForWorkflow);
        }
        return $userForWorkflow;
    }

    public function executeNode(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        $roamingData->setCurrentNode($node['id']);
        $moduleClass = $this->getModuleClass($node);
        if (!empty($moduleClass->disabled)) {
            $message = __('Could not execute disabled module `%s`.', $node['data']['id']);
            $this->logExecutionError($roamingData->getWorkflow(), $message);
            $errors[] = $message;
            $this->sendRequestToDebugEndpointIfDebug($roamingData->getWorkflow(), $node, sprintf('/exec/%s?result=%s', $moduleClass->id, 'disabled_module'), $roamingData->getData());
            return false;
        }
        if (!is_null($moduleClass)) {
            $execErrors = [];
            try {
                $success = $moduleClass->exec($node, $roamingData, $execErrors);
                if (!empty($execErrors)) {
                    $errors += $execErrors;
                }
            } catch (Exception $e) {
                $message = __('Error while executing module %s. Error: %s', $node['data']['id'], $e->getMessage());
                $this->logExecutionError($roamingData->getWorkflow(), $message);
                $errors[] = $message;
                $this->sendRequestToDebugEndpointIfDebug($roamingData->getWorkflow(), $node, sprintf('/exec/%s?result=%s&message=%s', $moduleClass->id, 'error', $e->getMessage()), $roamingData->getData());
                return false;
            }
        } else {
            $message = sprintf(__('Could not load class for module: %s'), $node['data']['id']);
            $this->logExecutionError($roamingData->getWorkflow(), $message);
            $errors[] = $message;
            $this->sendRequestToDebugEndpointIfDebug($roamingData->getWorkflow(), $node, sprintf('/exec/%s?result=%s', $node['data']['id'], 'loading_error'), $roamingData->getData());
            return false;
        }
        if (!empty($this->loaded_modules['logic'][$moduleClass->id])) { // IF module return false for the 2 output.
            $sucessType = 'success';
        } else {
            $sucessType = $success ? 'success' : 'partial-success';
        }
        $message = __('Executed node `%s`' .  PHP_EOL . 'Node `%s` (%s) from Workflow `%s` (%s) executed successfully with status: %s',
            $node['data']['id'],
            $node['data']['id'],
            $node['id'],
            $roamingData->getWorkflow()['Workflow']['name'],
            $roamingData->getWorkflow()['Workflow']['id'],
            $sucessType
        );
        $this->logExecutionIfDebug($roamingData->getWorkflow(), $message);
        $this->sendRequestToDebugEndpointIfDebug(
            $roamingData->getWorkflow(),
            $node,
            sprintf('/exec/%s?result=%s', $moduleClass->id, $sucessType),
            $roamingData->getData(),
            $execErrors
        );
        return $success;
    }

    private function __normalizeDataForTrigger($triggerClass, array $data)
    {
        if (method_exists($triggerClass, 'normalizeData')) {
            $data = $triggerClass->normalizeData($data);
        }
        return $data;
    }

    private function digestExecutionResult(array $walkResult)
    {
        if (empty($walkResult['Nodes that stopped execution'])) {
            return __('All nodes executed.');
        }
        $str = [];
        foreach ($walkResult['Nodes that stopped execution'] as $node) {
            $str[] = __('Node `%s` (%s) stopped execution.', $node['data']['id'], $node['id']);
        }
        return implode(', ', $str);
    }

    public function getModuleClass($node)
    {
        $this->loadAllWorkflowModules();
        $moduleClass = $this->loaded_classes[$node['data']['module_type']][$node['data']['id']] ?? null;
        return $moduleClass;
    }

    /**
     * getModuleClassByType
     *
     * @param string $module_type
     * @param string $id
     * @param boolean $throwException
     * @return
     * @throws ModuleNotFoundException
     */
    public function getModuleClassByType($module_type, $id, $throwException=false)
    {
        $this->loadAllWorkflowModules();
        $moduleClass = $this->loaded_classes[$module_type][$id] ?? null;
        if (is_null($moduleClass) && !empty($throwException)) {
            if ($module_type == 'trigger') {
                throw new TriggerNotFoundException(__('Unknown module `%s` for module type `%s`', $id, $module_type));
            } else {
                throw new ModuleNotFoundException(__('Unknown module `%s` for module type `%s`', $id, $module_type));
            }
        }
        return $moduleClass;
    }

    /**
     * getModuleConfigByType
     *
     * @param string $module_type
     * @param string $id
     * @param boolean $throwException
     * @return array
     * @throws ModuleNotFoundException
     */
    public function getModuleConfigByType($module_type, $id, $throwException=false): ?array
    {
        $this->loadAllWorkflowModules();
        $moduleConfig = $this->loaded_modules[$module_type][$id] ?? null;
        if (is_null($moduleConfig) && !empty($throwException)) {
            throw new ModuleNotFoundException(__('Unknown module `%s` for module type `%s`', $id, $module_type));
        }
        return $moduleConfig;
    }

    public function attachNotificationToModules(array $modules, array $workflow): array
    {
        $trigger_is_misp_core_format = false;
        $trigger_is_blocking = false;
        $trigger_id = $this->workflowGraphTool->extractTriggerFromWorkflow($workflow['Workflow']['data'], false);
        if (!empty($trigger_id)) {
            $triggerClass = $this->getModuleClassByType('trigger', $trigger_id, true);
            $trigger_is_misp_core_format = !empty($triggerClass->misp_core_format);
            $trigger_is_blocking = !empty($triggerClass->blocking);
        }
        foreach ($modules as $moduleType => $modulesByType) {
            foreach ($modulesByType as $i => $module) {
                $modules[$moduleType][$i]['notifications'] = !empty($module['notifications']) ? $module['notifications'] : [
                    'error' => [],
                    'warning' => [],
                    'info' => [],
                ];
                if ($module['disabled']) {
                    $modules[$moduleType][$i]['notifications']['error'][] = [
                        'text' => __('Module disabled'),
                        'description' => __('This module is disabled and thus will not be executed.'),
                        'details' => [
                            __('Disabled modules that are blocking will also stop the execution')
                        ],
                        '__show_in_sidebar' => false,
                        '__show_in_node' => true,
                    ];
                }
                if (!$trigger_is_blocking && !empty($module['blocking'])) {
                    $modules[$moduleType][$i]['notifications']['warning'][] = [
                        'text' => __('Blocking module might not work as intended'),
                        'description' => __('This module is a blocking module for a non-blocking trigger.'),
                        'details' => [
                            __('The Blocking modules will be executed. However, it will not block the remaining of the execution')
                        ],
                        '__show_in_sidebar' => true,
                        '__show_in_node' => true,
                    ];
                }
                if ($moduleType != 'modules_trigger') {
                    if (!$trigger_is_misp_core_format && !empty($module['expect_misp_core_format'])) {
                        $modules[$moduleType][$i]['notifications']['warning'][] = [
                            'text' => __('Potential data format issue'),
                            'description' => __('This module might not work properly as it expect data compliant with the MISP core format.'),
                            'details' => [
                                __('This module expect data to be compliant with the MISP core format. However, the data passed by the trigger might not be under this format.')
                            ],
                            '__show_in_sidebar' => true,
                            '__show_in_node' => true,
                        ];
                    }
                }
                if ($moduleType == 'modules_action') {
                    $moduleClass = $this->getModuleClassByType('action', $module['id']);
                    $diagnostic = $moduleClass->diagnostic();
                    $modules[$moduleType][$i]['notifications'] = array_merge_recursive($modules[$moduleType][$i]['notifications'], $diagnostic);
                }
            }
        }
        return $modules;
    }

    public function loadAllWorkflowModules()
    {
        if ($this->module_initialized) {
            return;
        }
        $phpModuleFiles = Workflow::__listPHPModuleFiles();
        foreach ($phpModuleFiles as $type => $files) {
            if ($type == 'custom') {
                continue;
            }
            $classModuleFromFiles = $this->__getClassFromModuleFiles($type, $files, false);
            foreach ($classModuleFromFiles['classConfigs'] as $i => $config) {
                $classModuleFromFiles['classConfigs'][$i]['module_type'] = $type;
            }
            $this->loaded_modules[$type] = $classModuleFromFiles['classConfigs'];
            $this->loaded_classes[$type] = $classModuleFromFiles['instancedClasses'];
        }
        // Load custom PHP modules from Lib
        foreach ($phpModuleFiles['custom'] as $type => $files) {
            $classModuleFromFiles = $this->__getClassFromModuleFiles($type, $files, true);
            foreach ($classModuleFromFiles['classConfigs'] as $i => $config) {
                $classModuleFromFiles['classConfigs'][$i]['module_type'] = $type;
            }
            $this->loaded_modules[$type] = array_merge($this->loaded_modules[$type], $classModuleFromFiles['classConfigs']);
            $this->loaded_classes[$type] = array_merge($this->loaded_classes[$type], $classModuleFromFiles['instancedClasses']);
        }
        // Load module from misp-module service
        $modules_from_service = $this->__getModulesFromModuleService() ?? [];
        $misp_module_class = $this->__getClassForMispModule($modules_from_service);
        $misp_module_configs = [];
        foreach ($misp_module_class as $i => $module_class) {
            $misp_module_configs[$i] = $module_class->getConfig();
            $misp_module_configs[$i]['module_type'] = 'action';
        }
        $this->loaded_modules['action'] = array_merge($this->loaded_modules['action'], $misp_module_configs);
        $this->loaded_classes['action'] = array_merge($this->loaded_classes['action'], $misp_module_class);
        $this->__mergeGlobalConfigIntoLoadedModules();
        $this->module_initialized = true;
    }

    private function __mergeGlobalConfigIntoLoadedModules()
    {
        foreach ($this->loaded_modules['trigger'] as &$trigger) {
            $module_disabled = empty(Configure::read(sprintf('Plugin.Workflow_triggers_%s', $trigger['id'])));
            $trigger['html_template'] = !empty($trigger['html_template']) ? $trigger['html_template'] : 'trigger';
            $trigger['disabled'] = $module_disabled;
            $this->loaded_classes['trigger'][$trigger['id']]->disabled = $module_disabled;
            $this->loaded_classes['trigger'][$trigger['id']]->html_template = !empty($trigger['html_template']) ? $trigger['html_template'] : 'trigger';
        }
        $enabledModules = $this->getEnabledModules();
        array_walk($this->loaded_modules['logic'], function (&$logic) use ($enabledModules) {
            $module_disabled = !in_array($logic['id'], $enabledModules);
            $logic['disabled'] = $module_disabled;
            $this->loaded_classes['logic'][$logic['id']]->disabled = $module_disabled;
        });
        array_walk($this->loaded_modules['action'], function (&$action) use ($enabledModules) {
            $module_disabled = !in_array($action['id'], $enabledModules);
            $action['disabled'] = $module_disabled;
            $this->loaded_classes['action'][$action['id']]->disabled = $module_disabled;
        });

    }

    private function __getEnabledModulesFromModuleService()
    {
        if (empty($this->Module)) {
            $this->Module = ClassRegistry::init('Module');
        }
        $enabledModules = $this->Module->getEnabledModules(null, 'Action');
        $misp_module_config = empty($enabledModules) ? false : $enabledModules;
        return $misp_module_config;
    }

    private function __getModulesFromModuleService()
    {
        if (empty($this->Module)) {
            $this->Module = ClassRegistry::init('Module');
        }
        $modules = $this->Module->getModules('Action');
        if (is_array($modules)) {
            foreach ($modules as $i => $temp) {
                if (!isset($temp['meta']['module-type']) || !in_array('action', $temp['meta']['module-type'])) {
                    unset($modules[$i]);
                }
            }
        }
        return $modules;
    }

    private function __getClassForMispModule($misp_module_configs)
    {
        $filepathMispModule = sprintf('%s/%s', Workflow::MODULE_ROOT_PATH, 'Module_misp_module.php');
        $className = 'Module_misp_module';
        $reflection = null;
        try {
            require_once($filepathMispModule);
            try {
                $reflection = new \ReflectionClass($className);
            } catch (\ReflectionException $e) {
                return $e->getMessage();
            }
        } catch (Exception $e) {
            return $e->getMessage();
        }
        $moduleClasses = [];
        if (is_array($misp_module_configs)) {
            foreach ($misp_module_configs as $moduleConfig) {
                $mainClass = $reflection->newInstance($moduleConfig);
                if ($mainClass->checkLoading() === 'The Factory Must Grow') {
                    $moduleClasses[$mainClass->id] = $mainClass;
                }
            }
        }
        return $moduleClasses;
    }

    /**
     * __listPHPModuleFiles List all PHP modules files
     *
     * @param boolean|array $targetDir If provided, will only collect files from that directory
     * @return array
     */
    private static function __listPHPModuleFiles($targetDir=false): array
    {
        $dirs = ['trigger', 'logic', 'action'];
        if (!empty($targetDir)) {
            $dirs = $targetDir;
        }
        $files = [];
        foreach ($dirs as $dir) {
            $folder = new Folder(Workflow::MODULE_ROOT_PATH . $dir);
            $filesInFolder = $folder->find('.*\.php', true);
            $files[$dir] = array_diff($filesInFolder, ['..', '.']);
            if ($dir == 'action' || $dir == 'logic') { // No custom module for the triggers
                $customFolder = new Folder(Workflow::CUSTOM_MODULE_ROOT_PATH . $dir);
                $filesInCustomFolder = $customFolder->find('.*\.php', true);
                $files['custom'][$dir] = array_diff($filesInCustomFolder, ['..', '.']);
            }
        }
        return $files;
    }

    private function __getClassFromModuleFiles($type, $files, $isCustom=false)
    {
        $instancedClasses = [];
        $classConfigs = [];
        foreach ($files as $filename) {
            $filepath = sprintf('%s%s/%s', (!empty($isCustom) ? Workflow::CUSTOM_MODULE_ROOT_PATH : Workflow::MODULE_ROOT_PATH), $type, $filename);
            $instancedClass = $this->__getClassFromModuleFile($filepath);
            if (is_string($instancedClass)) {
                $this->__logLoadingError($filename, $instancedClass);
                $this->error_while_loading[$filename] = $instancedClass;
                continue;
            }
            if (!empty($classConfigs[$instancedClass->id])) {
                throw new WorkflowDuplicatedModuleIDException(__('Module %s has already been defined', $instancedClass->id));
            }
            $classConfigs[$instancedClass->id] = $instancedClass->getConfig();
            $instancedClasses[$instancedClass->id] = $instancedClass;
            if (!empty($isCustom)) {
                $classConfigs[$instancedClass->id]['is_custom'] = true;
                $instancedClasses[$instancedClass->id]->is_custom = true;
            }
        }
        return [
            'classConfigs' => $classConfigs,
            'instancedClasses' => $instancedClasses,
        ];
    }

    public function logExecutionError($workflow, $message)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry('SYSTEM', 'execute_workflow', 'Workflow', $workflow['Workflow']['id'], $message);
        $this->__logToFile($workflow, $message);
    }

    public function logExecutionIfDebug(array $workflow, $message): void
    {
        if ($workflow['Workflow']['debug_enabled']) {
            $this->Log->createLogEntry('SYSTEM', 'execute_workflow', 'Workflow', $workflow['Workflow']['id'], $message);
            $this->__logToFile($workflow, $message);
        }
    }

    /**
     * __logToFile Log to file
     *
     * @param array $workflow
     * @param string $message
     * @return void
     */
    private function __logToFile($workflow, $message)
    {
        $logEntry = sprintf('[%s] Workflow(%s:%s). %s' . PHP_EOL, date('Y-m-d H:i:s'), $workflow['Workflow']['trigger_id'], $workflow['Workflow']['id'], $message);
        // file_put_contents(APP . 'tmp/logs/workflow-execution.log', $logEntry, FILE_APPEND | LOCK_EX);
        FileAccessTool::writeToFile(APP . 'tmp/logs/workflow-execution.log', $logEntry, false, true);
    }

    private function __logLoadingError($filename, $error)
    {
        $this->Log = ClassRegistry::init('Log');
        $message = __('Could not load module for file `%s`.', $filename);
        $this->Log->createLogEntry('SYSTEM', 'load_module', 'Workflow', 0, $message, $error);
    }

    /**
     * getProcessorClass
     *
     * @param  string $filePath
     * @param  string $processorMainClassName
     * @return object|string Object loading success, string containing the error if failure
     */
    private function __getClassFromModuleFile($filepath)
    {
        $className = explode('/', $filepath);
        $className = str_replace('.php', '', $className[count($className)-1]);
        try {
            if (!include_once($filepath)) {
                $message = __('Could not load module for path %s. File does not exist.', $filepath);
                $this->log($message, LOG_ERR);
                return $message;
            }
            try {
                $reflection = new \ReflectionClass($className);
            } catch (\ReflectionException $e) {
                $message = __('Could not load module for path %s. Could not instanciate class', $filepath);
                $this->logException($message, $e);
                return $message;
            }
            $mainClass = $reflection->newInstance();
            if ($mainClass->checkLoading() === 'The Factory Must Grow') {
                return $mainClass;
            }
        } catch (Exception $e) {
            $message = __('Could not load module for path %s', $filepath);
            $this->logException($message, $e);
            return $message;
        }
    }

    public function getModuleLoadingError(): array
    {
        return $this->error_while_loading;
    }

    public function getModulesByType($module_type=false): array
    {
        $this->loadAllWorkflowModules();

        $modules_trigger = $this->loaded_modules['trigger'];
        $modules_logic = $this->loaded_modules['logic'];
        $modules_action = $this->loaded_modules['action'];

        $this->__sortModulesByName($modules_trigger);
        $this->__sortModulesByName($modules_logic);
        $this->__sortModulesByName($modules_action);
        $modules_trigger = array_values($modules_trigger);
        $modules_logic = array_values($modules_logic);
        $modules_action = array_values($modules_action);
        $modules = [
            'modules_trigger' => $modules_trigger,
            'modules_logic' => $modules_logic,
            'modules_action' => $modules_action,
        ];
        if (!empty($module_type)) {
            if (!empty($modules['modules_' . $module_type])) {
                return $modules['modules_' . $module_type];
            } else {
                return [];
            }
        }
        return $modules;
    }

    private function __sortModulesByName(&$modules)
    {
        uasort($modules, function ($module1, $module2) {
            if ($module1['name'] == $module2['name']) {
                return 0;
            }
            return ($module1['name'] < $module2['name']) ? -1 : 1;
        });
    }

    public function getModules(): array
    {
        $modulesByType = $this->getModulesByType();
        return array_merge($modulesByType['modules_trigger'], $modulesByType['modules_logic'], $modulesByType['modules_action']);
    }

    /**
     * getModules Return the module from the provided ID
     *
     * @param string|array $module_ids
     * @return array
     */
    public function getModuleByID($module_ids): array
    {
        $returnAString = false;
        if (!is_array($module_ids)) {
            $returnAString = true;
            $module_ids = [$module_ids];
        }
        $matchingModules = [];
        $modules = $this->getModules();
        foreach ($modules as $module) {
            if (in_array($module['id'], $module_ids)) {
                $matchingModules[] = $module;
            }
        }
        if (empty($matchingModules)) {
            return [];
        }
        return $returnAString ? $matchingModules[0] : $matchingModules;
    }

    private function __incrementWorkflowExecutionCount(array $workflow): array
    {
        $workflow['Workflow']['counter'] = intval($workflow['Workflow']['counter']) + 1;
        $this->save($workflow, ['fieldList' => ['counter']]);
        return $this->fetchWorkflow($workflow['Workflow']['id']);
    }

    /**
     * fetchWorkflows
     *
     * @param  array $options
     * @param  bool  $full
     * @return array
     */
    public function fetchWorkflows(array $options = array(), $full = false)
    {
        $params = array(
            'contain' => $this->defaultContain,
            'recursive' => -1
        );
        if ($full) {
            $params['recursive'] = 1;
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['group'])) {
            $params['group'] = !empty($options['group']) ? $options['group'] : false;
        }
        if (isset($options['contain'])) {
            $params['contain'] = !empty($options['contain']) ? $options['contain'] : [];
        }

        $params['order'] = [];
        if (!empty($options['order'])) {
            $params['order'] = $this->findOrder(
                $options['order'],
                'Workflow',
                ['id', 'name', 'timestmap', 'trigger_id', 'counter']
            );
        }

        $workflows = $this->find('all', $params);
        return $workflows;
    }

    /**
     * fetchWorkflow
     *
     * @param  int|string $id
     * @param  bool $throwErrors
     * @throws NotFoundException
     * @return array
     */
    public function fetchWorkflow($id, bool $throwErrors = true): array
    {
        $options = [];
        if (is_numeric($id)) {
            $options = ['conditions' => ['Workflow.id' => $id]];
        } elseif (Validation::uuid($id)) {
            $options = ['conditions' => ['Workflow.uuid' => $id]];
        } else {
            if ($throwErrors) {
                throw new NotFoundException(__('Invalid workflow'));
            }
            return [];
        }
        $workflow = $this->fetchWorkflows($options);
        if (empty($workflow)) {
            if ($throwErrors) {
                throw new NotFoundException(__('Invalid workflow'));
            }
            return [];
        }
        return $workflow[0];
    }

    /**
     * fetchWorkflowByTrigger
     *
     * @param  int|string $trigger_id
     * @param  bool $throwErrors
     * @throws NotFoundException
     * @return array
     */
    public function fetchWorkflowByTrigger($trigger_id, bool $throwErrors = true): array
    {
        $options = [
            'conditions' => [
                'Workflow.trigger_id' => $trigger_id,
            ]
        ];
        $workflow = $this->fetchWorkflows($options);
        if (empty($workflow)) {
            if ($throwErrors) {
                throw new NotFoundException(__('Invalid workflow'));
            }
            return [];
        }
        return $workflow[0];
    }

    /**
     * addWorkflow Add a worflow
     *
     * @param  array $trigger
     * @return array Any errors preventing the edition
     */
    public function addWorkflow(array $workflow): array
    {
        $errors = [];
        $this->create();
        $saved = $this->__saveAndReturnErrors($workflow, ['fieldList' => self::CAPTURE_FIELDS_ADD], $errors);
        return [
            'saved' => $saved,
            'errors' => $errors,
        ];
    }

    /**
     * editWorkflow Edit a worflow
     *
     * @param  array $workflow
     * @return array Any errors preventing the edition
     */
    public function editWorkflow(array $workflow): array
    {
        $errors = [];
        if (!isset($workflow['Workflow']['uuid'])) {
            $errors[] = __('Workflow doesn\'t have an UUID');
            return $errors;
        }
        $existingWorkflow = $this->fetchWorkflow($workflow['Workflow']['id']);
        $workflow['Workflow']['id'] = $existingWorkflow['Workflow']['id'];
        unset($workflow['Workflow']['timestamp']);
        $saved = $this->__saveAndReturnErrors($workflow, ['fieldList' => self::CAPTURE_FIELDS_EDIT], $errors);
        return [
            'saved' => $saved,
            'errors' => $errors,
        ];
    }

    /**
     * genGraphDataForTrigger Generate fake graph data under the drawflow format
     *
     * @param string $trigger_id
     * @return array
     */
    public function genGraphDataForTrigger($trigger_id): array
    {
        if (empty($this->loaded_modules['trigger'][$trigger_id])) {
            throw new TriggerNotFoundException(__('Unknown trigger `%s`', $trigger_id));
        }
        $module_config = $this->loaded_modules['trigger'][$trigger_id];
        $data = [
            1 => [
                'class' => 'block-type-trigger',
                'data' => $module_config,
                'id' => 1,
                'inputs' => [],
                'outputs' => [
                    'output_1' => [
                        'connections' => []
                    ],
                ],
                'pos_x' => 0,
                'pos_y' => 0,
                'typenode' => false,
            ]
        ];
        return $data;
    }

    public function getLabelsForConnections($workflow, $trigger_id): array
    {
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        $startNodeID = $this->workflowGraphTool->getNodeIdForTrigger($graphData, $trigger_id);
        if ($startNodeID  == -1) {
            return [];
        }

        $connections = [];

        $filterNodes = $this->workflowGraphTool->extractFilterNodesFromWorkflow($graphData, true);
        $filterNodeIDToLabel = Hash::combine($filterNodes, '{n}.id', '{n}.data.indexed_params.filtering-label');
        $resetFilterNodes = $this->workflowGraphTool->extractResetFilterFromWorkflow($graphData, true);
        $resetFilterNodeIDToLabel = Hash::combine($resetFilterNodes, '{n}.id', '{n}.data.indexed_params.filtering-label');
        $roamingData = $this->workflowGraphTool->getRoamingData();
        $graphWalker = $this->workflowGraphTool->getWalkerIterator($graphData, $this, $startNodeID, GraphWalker::PATH_TYPE_INCLUDE_LOGIC, $roamingData);
        foreach ($graphWalker as $graphNode) {
            $node = $graphNode['node'];
            $nodeID = $node['id'];
            $parsedPathList = GraphWalker::parsePathList($graphNode['path_list']);
            if (!empty($parsedPathList)) {
                $lastNodeInPath = $parsedPathList[count($parsedPathList)-1];
                $previousNodeId = $lastNodeInPath['source_id'];
                $connections[$nodeID][$previousNodeId] = [];
            }
            foreach ($parsedPathList as $pathEntry) {
                if (!empty($filterNodeIDToLabel[$pathEntry['source_id']])) {
                    $connections[$nodeID][$previousNodeId][] = $filterNodeIDToLabel[$pathEntry['source_id']];
                }
                if (!empty($resetFilterNodeIDToLabel[$pathEntry['source_id']])) {
                    if ($resetFilterNodeIDToLabel[$pathEntry['source_id']] == 'all') {
                        $connections[$nodeID][$previousNodeId] = [];
                    } else {
                        $connections[$nodeID][$previousNodeId] = array_values(array_diff($connections[$nodeID][$previousNodeId], [$resetFilterNodeIDToLabel[$pathEntry['source_id']]]));
                    }
                }
            }
        }
        $connections = array_filter($connections, function($connection) {
            foreach ($connection as $labels) {
                if (!empty($labels)) {
                    return true;
                }
            }
            return false;
        });
        return $connections;
    }

    public function attachLabelToConnections($workflow, $trigger_id=null): array
    {
        $graphData = !empty($workflow['Workflow']) ? $workflow['Workflow']['data'] : $workflow['data'];
        if (is_null($trigger_id)) {
            $startNode = $this->workflowGraphTool->extractTriggerFromWorkflow($graphData, true);
            $trigger_id = $startNode['data']['id'];
        }
        $labelsByNodes = $this->getLabelsForConnections($workflow, $trigger_id);
        foreach ($graphData as $i => $node) {
            if ($i == '_frames') {
                continue;
            }
            if (!empty($labelsByNodes[$node['id']])) {
                foreach ($node['inputs'] as $inputName => $inputs) {
                    foreach ($inputs['connections'] as $j => $connection) {
                        $workflow['Workflow']['data'][$i]['inputs'][$inputName]['connections'][$j]['labels'] = array_map(function($label) {
                            return [
                                'id' => Inflector::variable($label),
                                'name' => $label,
                                'variant' => 'info',
                            ];
                        }, $labelsByNodes[$node['id']][$connection['node']]);
                    }
                }
            }
        }
        return $workflow;
    }
    /**
     * moduleSattelesExecution Executes a module using the provided configuration and returns back the result
     *
     * @param string $module_id
     * @param string|array $input_data
     * @param array $param_data
     * @return array
     */
    public function moduleStatelessExecution(string $module_id, $input_data=[], array $param_data=[], bool $convert_data=true): array
    {
        $result = [];
        $input_data = !empty($input_data) ? $input_data : [];
        $data = $input_data;
        if (!empty($convert_data)) {
            $eventPublishTrigger = $this->getModuleClassByType('trigger', 'event-publish');
            $data = $this->__normalizeDataForTrigger($eventPublishTrigger, $input_data);
        }
        $module_config = $this->getModuleByID($module_id);
        $node = $this->genNodeFromConfig($module_config, $param_data);
        $module_class = $this->getModuleClass($node);
        $user_for_workflow = $this->getUserForWorkflow();
        if (empty($user_for_workflow)) {
            $result['error'][] = __('Could not find a valid user to run the workflow. Please set setting `MISP.host_org_id` or make sure a valid site_admin user exists.');
            return $result;
        }
        $roaming_data = $this->workflowGraphTool->getRoamingData($user_for_workflow, $data);
        $errors = [];
        $success = $module_class->exec($node, $roaming_data, $errors);
        $result['success'] = $success;
        $result['errors'] = $errors;
        return $result;
    }

    public function genNodeFromConfig(array $module_config, $indexed_params): array
    {
        $node = [
            'id' => 1,
            'name' => $module_config['name'],
            'data' => [
                'id' => $module_config['id'],
                'name' => $module_config['name'],
                'module_type' => $module_config['module_type'],
                'module_version' => $module_config['version'],
                'indexed_params' => $indexed_params,
                'saved_filters' => $module_config['saved_filters'],
                'module_data' => $module_config,
                'expect_misp_core_format' => $module_config['expect_misp_core_format'],
            ],
            'inputs' => [],
            'outputs' => [],
        ];
        return $node;
    }

    /**
     * hasPathWarnings
     *
     * @param array $graphData
     * @param array $edges
     * @return boolean
     */
    public function hasPathWarnings(array $graphData, array &$edges=[])
    {
        $startNodes = $this->workflowGraphTool->extractConcurrentTasksFromWorkflow($graphData, true);
        $concurrentNodeIDs = Hash::extract($startNodes, '{n}.id');
        $roamingData = $this->workflowGraphTool->getRoamingData();
        foreach ($concurrentNodeIDs as $concurrentNodeID) {
            $graphWalker = $this->workflowGraphTool->getWalkerIterator($graphData, $this, $concurrentNodeID, GraphWalker::PATH_TYPE_INCLUDE_LOGIC, $roamingData);
            foreach ($graphWalker as $graphNode) {
                $moduleClass = $this->getModuleClass($graphNode['node']);
                if (!empty($moduleClass->blocking)) {
                    $parsedPathList = GraphWalker::parsePathList($graphNode['path_list']);
                    foreach ($parsedPathList as $pathEntry) {
                        $edges[] = [
                            $pathEntry['source_id'],
                            $pathEntry['next_node_id'],
                            __('This path leads to a blocking node from a non-blocking context'),
                            $moduleClass->blocking,
                            $moduleClass->id,
                            $graphNode['node']['id'],
                        ];
                    }
                }
            }
        }
        return !empty($edges);
    }

    private function __saveAndReturnErrors($data, $saveOptions = [], &$errors = [])
    {
        $saveSuccess = $this->save($data, $saveOptions);
        if (!$saveSuccess) {
            foreach ($this->validationErrors as $validationError) {
                $errors[] = $validationError[0];
            }
        } else {
            if (!empty($saveSuccess['Workflow']['data'])) {
                $saveSuccess['Workflow']['data'] = JsonTool::decode($saveSuccess['Workflow']['data']);
            }
        }
        return $saveSuccess;
    }

    public function sendRequestToDebugEndpointIfDebug(array $workflow, array $node, $path='/', array $data=[], array $errors=[])
    {
        if ($workflow['Workflow']['debug_enabled']) {
            $this->sendRequestToDebugEndpoint($workflow, $node, $path, $data, $errors);
        }
    }

    public function sendRequestToDebugEndpoint(array $workflow, array $node, $path='/', array $data=[],  array $errors=[])
    {
        $debug_url = Configure::read('Plugin.Workflow_debug_url');
        App::uses('HttpSocket', 'Network/Http');
        $socket = new HttpSocket([
            'timeout' => 5
        ]);
        $uri = sprintf('%s/%s%s', $debug_url, $workflow['Workflow']['trigger_id'], $path);
        $dataToPost = [
            'source' => [
                'node_id' => $node['id'] ?? '',
                'module_id' => $node['data']['id'] ?? '',
                'filters' => $node['data']['saved_filters'] ?? '',
                'parameters' => $node['data']['indexed_params'] ?? '',
            ],
            'timestamp' => date("c"),
            'data' => $data,
        ];
        if (!empty($errors)) {
            $dataToPost['errors'] = $errors;
        }
        $socket->post($uri, JsonTool::encode($dataToPost));
    }
    
    public function getDotNotation($id)
    {
        App::uses('GraphvizDOTTool', 'Tools');
        $workflow = $this->fetchWorkflow($id);
        $dot = GraphvizDOTTool::dot($workflow['Workflow']['data']);
        return $dot;
    }
    
    public function getMermaid($id)
    {
        App::uses('MermaidFlowchartTool', 'Tools');
        $workflow = $this->fetchWorkflow($id);
        $mermaid = MermaidFlowchartTool::mermaid($workflow['Workflow']['data']);
        return $mermaid;
    }
}
