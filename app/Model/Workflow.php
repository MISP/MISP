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

    const CAPTURE_FIELDS = ['name', 'description', 'timestamp', 'priority_level', 'data'];

    const WORKFLOW_BLOCKING_PATH_NAME = 'output_1';
    const WORKFLOW_NON_BLOCKING_PATH_NAME = 'output_2';

    const REDIS_KEY_WORKFLOW_PER_TRIGGER = 'workflow:workflow_list:%s';
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
                $results[$k]['Workflow']['listening_triggers'] = $this->getTriggersPerWorkflow((int) $result['Workflow']['id']);
            }
        }
        return $results;
    }

    public function afterSave($created, $options = array())
    {
        $this->updateListeningTriggers($this->data['Workflow']);
    }

    /**
     * updateListeningTriggers Regenerate the list of triggers that will run this workflow
     *  - collect trigger name for workflow
     *  - remove wf id from trigger list
     *  - remove trigger name from workflow
     *  - add wf id to trigger list
     *  - add trigger name to workflow
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
        $pipeline = $redis->pipeline();
        $trigger_list = $this->getTriggersPerWorkflow((int)$workflow['Workflow']['id']);
        foreach ($trigger_list as $trigger_name) {
            $pipeline->sRem(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_name), $workflow['Workflow']['id']);
            $pipeline->sRem(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow['Workflow']['id']), $trigger_name);
        }
        $listening_triggers = $this->extractTriggerFromWorkflow($workflow);
        foreach ($listening_triggers as $trigger_name) {
            $pipeline->sAdd(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_name), $workflow['Workflow']['id']);
            $pipeline->sAdd(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow['Workflow']['id']), $trigger_name);
        }
        $pipeline->exec();
    }

    /**
     * getWorkflowsPerTrigger Get list of workflow IDs listening to the specified trigger
     *
     * @param  string $workflow
     */
    private function getWorkflowsPerTrigger(string $trigger_name)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        return $redis->sMembers(sprintf(Workflow::REDIS_KEY_WORKFLOW_PER_TRIGGER, $trigger_name));
    }

    /**
     * getTriggersPerWorkflow Get list of trigger name running to the specified workflow
     *
     * @param  array $workflow
     */
    private function getTriggersPerWorkflow(int $workflow_id)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        return $redis->sMembers(sprintf(Workflow::REDIS_KEY_TRIGGER_PER_WORKFLOW, $workflow_id));
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
        $workflow_IDs = [];
        $workflows_per_trigger = [];
        foreach ($triggers as $trigger) {
            $workflow_IDs_for_trigger = $this->getWorkflowsPerTrigger($trigger['id']);
            $workflows_per_trigger[$trigger['id']] = $workflow_IDs_for_trigger;
            foreach ($workflow_IDs_for_trigger as $id) {
                $workflow_IDs[$id] = true;
            }
        }
        $workflow_IDs = array_keys($workflow_IDs);
        $workflows = $this->fetchWorkflows($user, [
            'conditions' => [
                'Workflow.id' => $workflow_IDs
            ],
            'fields' => ['*'],
            'contain' => ['Organisation' => ['fields' => ['*']]],
        ]);
        $workflows = Hash::combine($workflows, '{n}.Workflow.id', '{n}');
        foreach ($triggers as $i => $trigger) {
            $workflow_IDs = $workflows_per_trigger[$trigger['id']];
            $triggers[$i]['Workflows'] = [];
            foreach ($workflow_IDs as $workflow_ID) {
                $triggers[$i]['Workflows'][] = $workflows[$workflow_ID];
            }
            usort($triggers[$i]['Workflows'], function($a, $b) {
                return $a['Workflow']['priority_level'] - $b['Workflow']['priority_level'];
            }); 
            if (!empty($group_per_blocking)) {
                $triggers[$i]['Workflows'] = $this->groupWorkflowsPerBlockingType($triggers[$i]['Workflows'], $trigger['id']);
            }
        }
        return $triggers;
    }

    /**
     * groupWorkflowsPerBlockingType Group workflows together if they have a blocking path set
     *
     * @param  array $workflows
     * @param  string $trigger_name The trigger for which we should decide if it's blocking or not
     * @return array
     */
    public function groupWorkflowsPerBlockingType(array $workflows, string $trigger_name): array
    {
        $groupedWorkflows = [
            'blocking' => [],
            'non-blocking' => [],
        ];
        foreach ($workflows as $workflow) {
            foreach ($workflow['Workflow']['data'] as $block) {
                if ($block['data']['id'] == $trigger_name) {
                    if (!empty($block['outputs'][Workflow::WORKFLOW_BLOCKING_PATH_NAME])) {
                        $groupedWorkflows['blocking'][] = $workflow;
                    }
                    if (!empty($block['outputs'][Workflow::WORKFLOW_NON_BLOCKING_PATH_NAME])) {
                        $groupedWorkflows['non-blocking'][] = $workflow;
                    }
                }
            }
        }
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

    public function getModules(): array
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
        });
        return [
            'blocks_trigger' => $blocks_trigger,
            'blocks_logic' => $blocks_logic,
            'blocks_action' => $blocks_action,
            'blocks_all' => array_merge($blocks_trigger, $blocks_logic, $blocks_action),
        ];
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