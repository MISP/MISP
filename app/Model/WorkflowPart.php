<?php
App::uses('AppModel', 'Model');

class WorkflowPart extends AppModel
{
    public $recursive = -1;

    public $actsAs = [
        'AuditLog',
        'Containable',
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
        if (empty($this->data['WorkflowPart']['uuid'])) {
            $this->data['WorkflowPart']['uuid'] = CakeText::uuid();
        } else {
            $this->data['WorkflowPart']['uuid'] = strtolower($this->data['WorkflowPart']['uuid']);
        }
        if (empty($this->data['WorkflowPart']['data'])) {
            $this->data['WorkflowPart']['data'] = [];
        }
        if (empty($this->data['WorkflowPart']['timestamp'])) {
            $this->data['WorkflowPart']['timestamp'] = time();
        }
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (empty($result['WorkflowPart']['data'])) {
                $result['WorkflowPart']['data'] = '{}';
            }
            $results[$k]['WorkflowPart']['data'] = JsonTool::decode($result['WorkflowPart']['data']);
        }
        return $results;
    }

    public function beforeSave($options = [])
    {
        if (is_array($this->data['WorkflowPart']['data'])) {
            $this->data['WorkflowPart']['data'] = JsonTool::encode($this->data['WorkflowPart']['data']);
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