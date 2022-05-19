<?php
App::uses('AppModel', 'Model');
class Workflow extends AppModel
{
    public $recursive = -1;

    public $actsAs = [
        'AuditLog',
        'Containable',
    ];

    public $belongsTo = [
        'User' => [
            'className' => 'User',
            'foreignKey' => 'user_id',
        ],
        'Organisation' => [
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        ]
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
    ];

    public $defaultContain = [
        // 'Organisation',
        // 'User'
    ];

    const CAPTURE_FIELDS = ['name', 'description', 'timestamp', 'data'];

    const WORKFLOW_BLOCKING_PATH_NAME = 'output_1';
    const WORKFLOW_NON_BLOCKING_PATH_NAME = 'output_2';

    const REDIS_KEY_WORKFLOW_PER_TRIGGER = 'workflow:workflow_list:%s';
    const REDIS_KEY_WORKFLOW_ORDER_PER_BLOCKING_TRIGGER = 'workflow:workflow_blocking_order_list:%s';
    const REDIS_KEY_TRIGGER_PER_WORKFLOW = 'workflow:trigger_list:%s';

    private $moduleByID = [];

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['Workflow']['data'])) {
            $this->data['Workflow']['data'] = [];
        }
        if (empty($this->data['Workflow']['timestamp'])) {
            $this->data['Workflow']['timestamp'] = time();
        }
        $this->data['Workflow']['data'] = JsonTool::encode($this->data['Workflow']['data']);
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
                $trigger_ids = $this->getTriggersIDPerWorkflow((int) $result['Workflow']['id']);
                $results[$k]['Workflow']['listening_triggers'] = $this->getModuleByID($trigger_ids);
            }
        }
        return $results;
    }

    public function afterSave($created, $options = array())
    {
        $this->updateListeningTriggers($this->data['Workflow']);
    }

    /**
     * updateListeningTriggers 
     *  - Update the list of triggers that will be run this workflow
     *  - Update the list of workflows that are run by their triggers
     *  - Update the ordered list of workflows that are run by their triggers
     *
     * @param  array $workflow
     */
    private function updateListeningTriggers($workflow)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        $workflow = $this->data;
        $workflow['Workflow']['data'] = JsonTool::decode($workflow['Workflow']['data']);
        $pipeline = $redis->multi();
        $trigger_list = $this->getTriggersIDPerWorkflow((int)$workflow['Workflow']['id']);
        foreach ($trigger_list as $trigger_id) {
            $pipeline->sRem(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_id), $workflow['Workflow']['id']);
            $pipeline->sRem(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow['Workflow']['id']), $trigger_id);
            $pipeline->lRem(sprintf(Workflow::REDIS_KEY_WORKFLOW_ORDER_PER_BLOCKING_TRIGGER, $trigger_id), $workflow['Workflow']['id'], 0);
        }
        $listening_triggers = $this->extractTriggerFromWorkflow($workflow);
        foreach ($listening_triggers as $trigger_id) {
            $pipeline->sAdd(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_id), $workflow['Workflow']['id']);
            $pipeline->sAdd(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow['Workflow']['id']), $trigger_id);
            $pipeline->rPush(sprintf(Workflow::REDIS_KEY_WORKFLOW_ORDER_PER_BLOCKING_TRIGGER, $trigger_id), $workflow['Workflow']['id']);
        }
        $pipeline->exec();
    }

    /**
     * getWorkflowsIDPerTrigger Get list of workflow IDs listening to the specified trigger
     *
     * @param  string $trigger_id
     * @return array
     */
    private function getWorkflowsIDPerTrigger($trigger_id): array
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
     * getOrderedWorkflowsPerTrigger Get list of workflow IDs in the execution order for the specified trigger
     *
     * @param  string $trigger_id
     * @return bool|array
     */
    private function getOrderedWorkflowsPerTrigger($trigger_id)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        return $redis->lRange(sprintf(Workflow::REDIS_KEY_WORKFLOW_ORDER_PER_BLOCKING_TRIGGER, $trigger_id), 0, -1);
    }

    /**
     * getTriggersIDPerWorkflow Get list of trigger name running to the specified workflow
     *
     * @param  int $workflow_id
     * @return bool|array
     */
    private function getTriggersIDPerWorkflow(int $workflow_id)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        return $redis->sMembers(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow_id));
    }

    /**
     * saveBlockingWorkflowExecutionOrder Get list of trigger name running to the specified workflow
     *
     * @param  string $trigger_id
     * @param  array $workflows List of workflow IDs in priority order
     * @return bool
     */
    public function saveBlockingWorkflowExecutionOrder($trigger_id, array $workflow_order): bool
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        $key = sprintf(Workflow::REDIS_KEY_WORKFLOW_ORDER_PER_BLOCKING_TRIGGER, $trigger_id);
        $pipeline = $redis->multi();
        $pipeline->del($key);
        foreach ($workflow_order as $workflow_id) {
            $pipeline->rpush($key, (string)$workflow_id);
        }
        $pipeline->exec();
        return true;
    }

    /**
     * getTriggerFromWorkflow Return the list of trigger names that are specified in the workflow
     *
     * @param  array $workflow
     * @return array
     */
    public function extractTriggerFromWorkflow(array $workflow)
    {
        $triggers = [];
        foreach ($workflow['Workflow']['data'] as $node) {
            if ($node['data']['module_type'] == 'trigger') {
                $triggers[] = $node['data']['id'];
            }
        }
        return $triggers;
    }

    /**
     * buildACLConditions Generate ACL conditions for viewing the workflow
     *
     * @param  array $user
     * @return array
     */
    public function buildACLConditions(array $user)
    {
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $conditions['Workflow.org_id'] = $user['org_id'];
        }
        return $conditions;
    }

    public function canEdit(array $user, array $workflow)
    {
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (empty($workflow['Workflow'])) {
            return __('Could not find associated workflow');
        }
        if ($workflow['Workflow']['user_id'] != $user['id']) {
            return __('Only the creator user of the workflow can modify it');
        }
        return true;
    }

    private function loadModuleByID()
    {
        if (empty($this->moduleByID)) {
            $modules = $this->getModules();
            foreach ($modules['blocks_all'] as $module) {
                $this->moduleByID[$module['id']] = $module;
            }
        }
    }

    /**
     * attachWorkflowsToTriggers Collect the workflows listening to this trigger
     *
     * @param  array $user
     * @param  array $triggers
     * @param  bool $group_per_blocking Wheter or not the workflows should be grouped together if they have a blocking path set
     * @return array
     */
    public function attachWorkflowsToTriggers(array $user, array $triggers, bool $group_per_blocking=true): array
    {
        $all_workflow_ids = [];
        $workflows_per_trigger = [];
        $ordered_workflows_per_trigger = [];
        foreach ($triggers as $trigger) {
            $workflow_ids_for_trigger = $this->getWorkflowsIDPerTrigger($trigger['id']);
            $workflows_per_trigger[$trigger['id']] = $workflow_ids_for_trigger;
            $ordered_workflows_per_trigger[$trigger['id']] = $this->getOrderedWorkflowsPerTrigger($trigger['id']);
            foreach ($workflow_ids_for_trigger as $id) {
                $all_workflow_ids[$id] = true;
            }
        }
        $all_workflow_ids = array_keys($all_workflow_ids);
        $workflows = $this->fetchWorkflows($user, [
            'conditions' => [
                'Workflow.id' => $all_workflow_ids,
            ],
            'fields' => ['*'],
            'contain' => ['Organisation' => ['fields' => ['*']]],
        ]);
        $workflows = Hash::combine($workflows, '{n}.Workflow.id', '{n}');
        foreach ($triggers as $i => $trigger) {
            $workflow_ids = $workflows_per_trigger[$trigger['id']];
            $ordered_workflow_ids = $ordered_workflows_per_trigger[$trigger['id']];
            $triggers[$i]['Workflows'] = [];
            foreach ($workflow_ids as $workflow_id) {
                $triggers[$i]['Workflows'][] = $workflows[$workflow_id];
            }
            if (!empty($group_per_blocking)) {
                $triggers[$i]['GroupedWorkflows'] = $this->groupWorkflowsPerBlockingType($triggers[$i]['Workflows'], $trigger['id'], $ordered_workflow_ids);
            }
        }
        return $triggers;
    }

    public function fetchWorkflowsForTrigger($user, $trigger_id): array
    {
        $workflow_ids_for_trigger = $this->getWorkflowsIDPerTrigger($trigger_id);
        $workflows = $this->fetchWorkflows($user, [
            'conditions' => [
                'Workflow.id' => $workflow_ids_for_trigger,
            ],
            'fields' => ['*'],
            'contain' => ['Organisation' => ['fields' => ['*']]],
        ]);
        return $workflows;
    }

    /**
     * getExecutionPathsForTrigger Generate the e
     *
     * @param  array $triggers
     * @param  bool $group_per_blocking Wheter or not the workflows should be grouped together if they have a blocking path set
     * @return array
     */
    public function getExecutionOrderForTrigger(array $user, array $trigger, bool $group_per_blocking=true): array
    {
        $workflows = $this->fetchWorkflowsForTrigger($user, $trigger['id']);
        $ordered_workflow_ids = $this->getOrderedWorkflowsPerTrigger($trigger['id']);
        return $this->groupWorkflowsPerBlockingType($workflows, $trigger['id'], $ordered_workflow_ids);
    }

    /**
     * groupWorkflowsPerBlockingType Group workflows together if they have a blocking path set
     *
     * @param  array $workflows
     * @param  string $trigger_id The trigger for which we should decide if it's blocking or not
     * @param  array $ordered_workflow_ids If provided, will sort the blocking workflows based on the workflow_id order in of the provided list
     * @return bool|array
     */
    public function groupWorkflowsPerBlockingType(array $workflows, $trigger_id, $ordered_workflow_ids=false): array
    {
        $groupedWorkflows = [
            'blocking' => [],
            'non-blocking' => [],
        ];
        foreach ($workflows as $workflow) {
            foreach ($workflow['Workflow']['data'] as $block) {
                if ($block['data']['id'] == $trigger_id) {
                    if (!empty($block['outputs'][Workflow::WORKFLOW_BLOCKING_PATH_NAME])) {
                        $order_index = array_search($workflow['Workflow']['id'], $ordered_workflow_ids);
                        $groupedWorkflows['blocking'][$order_index] = $workflow;
                    }
                    if (!empty($block['outputs'][Workflow::WORKFLOW_NON_BLOCKING_PATH_NAME])) {
                        $groupedWorkflows['non-blocking'][] = $workflow;
                    }
                }
            }
        }
        ksort($groupedWorkflows['blocking']);
        return $groupedWorkflows;
    }

    public function getExecutionPath($user, $id): array
    {
        $this->loadModuleByID();
        $workflow = $this->fetchWorkflow($user, $id);
        $trigger_modules = [];
        $workflowData = [];
        foreach ($workflow['Workflow']['data'] as $node) { // Re-index data by node ID
            $workflowData[$node['id']] = $node;
        }
        // collect trigger block acting as starting point
        foreach ($workflowData as $node_id => $node) {
            $module = $this->moduleByID[$node['data']['id']];
            if ($module['module_type'] == 'trigger') {
                $trigger_modules[] = $node;
            }
        }
        // construct execution flow following outputs/inputs of each  blocks
        $processedNodeIDs = [];
        foreach ($trigger_modules as $i => $trigger_module) {
            $this->buildExecutionPathViaConnections($trigger_modules[$i], $workflowData, $processedNodeIDs);
        }
        $execution_path = [];
        foreach ($trigger_modules as $module) {
            $execution_path[] = $this->cleanNode($module);
        }
        return $execution_path;
    }

    public function buildExecutionPathViaConnections(&$node, $allData, &$processedNodeIDs)
    {
        if (!empty($processedNodeIDs[$node['id']])) { // Prevent infinite loop
            return $node;
        }
        $processedNodeIDs[$node['id']] = true;
        if (!empty($node['outputs'])) {
            foreach ($node['outputs'] as $output_id => $outputs) {
                foreach ($outputs as $connections) {
                    foreach ($connections as $connection) {
                        $nextNode = $this->buildExecutionPathViaConnections($allData[$connection['node']], $allData, $processedNodeIDs);
                        $node['next'][] = $this->cleanNode($nextNode);
                    }
                }
            }
        }
        return $node;
    }

    public function cleanNode($node): array
    {
        return [
            'id' => $node['id'],
            'data' => $node['data'],
            'module_data' => $this->moduleByID[$node['data']['id']],
            'next' => $node['next'] ?? [],
        ];
    }

    public function getModules($module_type=false): array
    {
        $blocks_trigger = [
            [
                'id' => 'publish',
                'name' => 'Publish',
                'icon' => 'upload',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'outputs' => 2,
            ],
            [
                'id' => 'new-attribute',
                'name' => 'New Attribute',
                'icon' => 'cube',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                // 'disabled' => true,
                'outputs' => 2,
            ],
            [
                'id' => 'new-object',
                'name' => 'New Object',
                'icon' => 'cubes',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
                'outputs' => 2,
            ],
            [
                'id' => 'email-sent',
                'name' => 'Email sent',
                'icon' => 'envelope',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
            ],
            [
                'id' => 'user-new',
                'name' => 'New User',
                'icon' => 'user-plus',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
                'outputs' => 2,
            ],
            [
                'id' => 'feed-pull',
                'name' => 'Feed pull',
                'icon' => 'arrow-alt-circle-down',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
            ],
        ];

        $blocks_logic = [
            [
                'id' => 'if',
                'name' => 'IF',
                'icon' => 'code-branch',
                'description' => 'IF conditions',
                'module_type' => 'logic',
                'outputs' => 2,
                'html_template' => 'IF',
                'params' => [
                    [
                        'type' => 'textarea',
                        'label' => 'Event Conditions',
                        'default' => '',
                        'placeholder' => '{ "tags" : { "AND" : [ "tlp : green" , "Malware" ] , "NOT" : [ "%ransomware%" ]}}'
                    ],
                ],
            ],
        ];

        $blocks_action = [
            [
                'id' => 'add-tag',
                'name' => 'Add Tag',
                'icon' => 'tag',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'input',
                        'label' => 'Tag name',
                        'default' => 'tlp:red',
                        'placeholder' => __('Enter tag name')
                    ],
                ],
                'outputs' => 0,
                // 'disabled' => true,
            ],
            [
                'id' => 'enrich-attribute',
                'name' => 'Enrich Attribute',
                'icon' => 'asterisk',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'outputs' => 0,
                'disabled' => true,
            ],
            [
                'id' => 'slack-message',
                'name' => 'Slack Message',
                'icon' => 'slack',
                'icon_class' => 'fab',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'select',
                        'label' => 'Channel name',
                        'default' => 'team-4_3_misp',
                        'options' => [
                            'team-4_3_misp' => __('Team 4.3 MISP'),
                            'team-4_0_elite_as_one' => __('Team 4.0 Elite as One'),
                        ],
                    ],
                ],
                'outputs' => 0,
            ],
            [
                'id' => 'matter-message',
                'name' => 'MatterMost Message',
                'icon' => 'comment-dots',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'input',
                        'label' => 'Tag name',
                        'default' => 'tlp:red',
                        'placeholder' => __('Enter tag name')
                    ],
                    [
                        'id' => 'channel_name_select',
                        'type' => 'select',
                        'label' => 'Channel name',
                        'default' => 'team-4_3_misp',
                        'options' => [
                            'team-4_3_misp' => __('Team 4.3 MISP'),
                            'team-4_0_elite_as_one' => __('Team 4.0 Elite as One'),
                        ],
                    ],
                    [
                        'id' => 'channel_name_radio',
                        'type' => 'radio',
                        'label' => 'Channel name',
                        'default' => 'team-4_3_misp',
                        'options' => [
                            'team-4_3_misp' => __('Team 4.3 MISP'),
                            'team-4_0_elite_as_one' => __('Team 4.0 Elite as One'),
                        ],
                    ],
                    [
                        'type' => 'checkbox',
                        'label' => __('Priority'),
                        'default' => true,
                    ],
                ],
                'outputs' => 0,
            ],
            [
                'id' => 'send-email',
                'name' => 'Send Email',
                'icon' => 'envelope',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'select',
                        'label' => 'Email template',
                        'default' => 'default',
                        'options' => [
                            'default',
                            'TLP marking',
                        ],
                    ],
                ],
                'outputs' => 0,
                'disabled' => true,
            ],
            [
                'name' => 'Do nothing',
                'id' => 'dev-null',
                'icon' => 'ban',
                'description' => 'Essentially a /dev/null',
                'module_type' => 'action',
                'outputs' => 0,
            ],
            [
                'name' => 'Push to ZMQ',
                'id' => 'push-zmq',
                'icon' => 'wifi',
                'icon_class' => 'fa-rotate-90',
                'description' => 'Push to the ZMQ channel',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'input',
                        'label' => 'ZMQ Topic',
                        'default' => 'from-misp-workflow',
                    ],
                ],
                'outputs' => 0,
                'disabled' => true,
            ],
        ];

        array_walk($blocks_trigger, function(&$block) {
            $block['html_template'] = !empty($block['html_template']) ? $block['html_template'] : 'trigger';
            $block['disabled'] = !empty($block['disabled']);
        });
        $modules = [
            'blocks_trigger' => $blocks_trigger,
            'blocks_logic' => $blocks_logic,
            'blocks_action' => $blocks_action,
            'blocks_all' => array_merge($blocks_trigger, $blocks_logic, $blocks_action),
        ];
        if (!empty($module_type)) {
            if (!empty($modules[$module_type])) {
                return $modules['block_' . $module_type];
            } else {
                return [];
            }
        }
        return $modules;
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
        $modules = $this->getModules()['blocks_all'];
        foreach ($modules as $module) {
            if (in_array($module['id'], $module_ids)) {
                $matchingModules[] = $module;
            }
        }
        return $returnAString ? $matchingModules[0] : $matchingModules;
    }

    /**
     * fetchWorkflows ACL-aware method. Basically find with ACL
     *
     * @param  array $user
     * @param  array $options
     * @param  bool  $full
     * @return array
     */
    public function fetchWorkflows(array $user, array $options = array(), $full = false)
    {
        $params = array(
            'conditions' => $this->buildACLConditions($user),
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
        if (isset($options['order'])) {
            $params['order'] = !empty($options['order']) ? $options['order'] : [];
        }
        $workflows = $this->find('all', $params);
        return $workflows;
    }

    /**
     * fetchWorkflow ACL-aware method. Basically find with ACL
     *
     * @param  array $user
     * @param  int|string $id
     * @param  bool $throwErrors
     * @return array
     */
    public function fetchWorkflow(array $user, $id, bool $throwErrors = true)
    {
        $options = [];
        if (is_numeric($id)) {
            $options = ['conditions' => ["Workflow.id" => $id]];
        } elseif (Validation::uuid($id)) {
            $options = ['conditions' => ["Workflow.uuid" => $id]];
        } else {
            if ($throwErrors) {
                throw new NotFoundException(__('Invalid workflow'));
            }
            return [];
        }
        $workflow = $this->fetchWorkflows($user, $options);
        if (empty($workflow)) {
            throw new NotFoundException(__('Invalid workflow'));
        }
        return $workflow[0];
    }

    /**
     * editWorkflow Edit a worflow
     *
     * @param  array $user
     * @param  array $workflow
     * @return array Any errors preventing the edition
     */
    public function editWorkflow(array $user, array $workflow)
    {
        $errors = array();
        if (!isset($workflow['Workflow']['uuid'])) {
            $errors[] = __('Workflow doesn\'t have an UUID');
            return $errors;
        }
        $existingWorkflow = $this->fetchWorkflow($user, $workflow['Workflow']['id']);
        $workflow['Workflow']['id'] = $existingWorkflow['Workflow']['id'];
        unset($workflow['Workflow']['timestamp']);
        $errors = $this->saveAndReturnErrors($workflow, ['fieldList' => self::CAPTURE_FIELDS], $errors);
        return $errors;
    }

    /**
     * fetchWorkflow ACL-aware method. Basically find with ACL
     *
     * @param  array $user
     * @param  int|string $id
     * @param  bool $enable
     * @param  bool $throwErrors
     * @return array
     */
    public function toggleWorkflow(array $user, $id, $enable=true, bool $throwErrors=true)
    {
        $errors = array();
        $workflow = $this->fetchWorkflow($user, $id, $throwErrors);
        $workflow['Workflow']['enabled'] = $enable;
        $errors = $this->saveAndReturnErrors($workflow, ['fieldList' => ['enabled']], $errors);
        return $errors;
    }

    private function saveAndReturnErrors($data, $saveOptions = [], $errors = [])
    {
        $saveSuccess = $this->save($data, $saveOptions);
        if (!$saveSuccess) {
            foreach ($this->validationErrors as $validationError) {
                $errors[] = $validationError[0];
            }
        }
        return $errors;
    }
    
}