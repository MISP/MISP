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
        'Organisation',
        'User'
    ];

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['Workflow']['data'])) {
            $this->data['Workflow']['data'] = [];
        }
        $this->data['Workflow']['data'] = JsonTool::encode($this->data['Workflow']['data']);
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (empty($result['Workflow']['data'])) {
                $result['Workflow']['data'] = '[]';
            }
            $results[$k]['Workflow']['data'] = JsonTool::decode($result['Workflow']['data']);
        }
        return $results;
    }

    /**
     * buildACLConditions Generate ACL conditions for viewing the report
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

    public function getModules(): array
    {
        return [];
    }

    /**
     * fetchReports ACL-aware method. Basically find with ACL
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
            $params['group'] = empty($options['group']) ? $options['group'] : false;
        }
        $workflows = $this->find('all', $params);
        return $workflows;
    }

    /**
     * fetchReports ACL-aware method. Basically find with ACL
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
        return $workflow;
    }
}