<?php
App::uses('AppModel', 'Model');

class WorkflowBlueprint extends AppModel
{
    public $recursive = -1;

    public $actsAs = [
        'AuditLog',
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
    ];

    const CAPTURE_FIELDS = ['name', 'description', 'timestamp', 'data'];

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['WorkflowBlueprint']['uuid'])) {
            $this->data['WorkflowBlueprint']['uuid'] = CakeText::uuid();
        } else {
            $this->data['WorkflowBlueprint']['uuid'] = strtolower($this->data['WorkflowBlueprint']['uuid']);
        }
        if (empty($this->data['WorkflowBlueprint']['data'])) {
            $this->data['WorkflowBlueprint']['data'] = [];
        }
        if (empty($this->data['WorkflowBlueprint']['timestamp'])) {
            $this->data['WorkflowBlueprint']['timestamp'] = time();
        }
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (empty($result['WorkflowBlueprint']['data'])) {
                $result['WorkflowBlueprint']['data'] = '{}';
            }
            $results[$k]['WorkflowBlueprint']['data'] = JsonTool::decode($result['WorkflowBlueprint']['data']);
        }
        return $results;
    }

    public function beforeSave($options = [])
    {
        if (is_array($this->data['WorkflowBlueprint']['data'])) {
            $this->data['WorkflowBlueprint']['data'] = JsonTool::encode($this->data['WorkflowBlueprint']['data']);
        }
        return true;
    }


    public function logExecutionError($workflow, $message)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry('SYSTEM', 'execute_workflow', 'Workflow', $workflow['Workflow']['id'], $message);
    }

    private function __logError($id, $message)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry('SYSTEM', 'load_module', 'Workflow', $id, $message);
        return false;
    }

    private function __saveAndReturnErrors($data, $saveOptions = [], $errors = [])
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