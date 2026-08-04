<?php
App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');

class WorkflowBlueprint extends AppModel
{
    const REPOSITORY_PATH = APP . 'files' . DS . 'misp-workflow-blueprints' . DS . 'blueprints';
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


    public $validate = [
        'name' => 'stringNotEmpty',
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
            $blueprint = $this->attachModuleDataToBlueprint($results[$k]);
            if (!empty($results[$k]['WorkflowBlueprint']['data'])) {
                $results[$k]['WorkflowBlueprint']['mermaid'] = $this->getMermaidForData($blueprint['WorkflowBlueprint']['data']);
            }
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

    public function attachModuleDataToBlueprint(array $blueprint)
    {
        $this->Workflow = ClassRegistry::init('Workflow');
        foreach ($blueprint['WorkflowBlueprint']['data'] as $i => $node) {
            $module = $this->Workflow->getModuleConfigByType($node['data']['module_type'], $node['data']['id']);
            $blueprint['WorkflowBlueprint']['data'][$i]['data']['module_data'] = $module;
        }
        return $blueprint;
    }

    /**
     * __readBlueprintsFromRepo Reads blueprints from the misp-workflow-blueprints repository
     *
     * @return array
     * @throws Exception
     */
    private function __readBlueprintsFromRepo(): array
    {
        $dir = new Folder(self::REPOSITORY_PATH);
        $files = $dir->find('.*\.json');
        $blueprints = [];
        foreach ($files as $file) {
            $blueprints[] = FileAccessTool::readJsonFromFile($dir->pwd() . DS . $file);
        }
        return $blueprints;
    }

    /**
     * update Update the blueprint using the default repository
     *
     * @param boolean $force
     * @return void
     * @throws Exception
     */
    public function update($force=false)
    {
        $blueprints_from_repo = $this->__readBlueprintsFromRepo();
        if (empty($blueprints_from_repo)) {
            throw new NotFoundException(__('Default blueprints could not be loaded or `%s` folder is empty', self::REPOSITORY_PATH));
        }
        $existing_blueprints = $this->find('all', [
            'recursive' => -1
        ]);
        $existing_blueprints_by_uuid = Hash::combine($existing_blueprints, '{n}.WorkflowBlueprint.uuid', '{n}.WorkflowBlueprint');
        foreach ($blueprints_from_repo as $blueprint_from_repo) {
            $blueprint_from_repo = $blueprint_from_repo['WorkflowBlueprint'];
            $blueprint_from_repo['default'] = true;
            if (!empty($existing_blueprints_by_uuid[$blueprint_from_repo['uuid']])) {
                $existing_blueprint = $existing_blueprints_by_uuid[$blueprint_from_repo['uuid']];
                if ($force || $blueprint_from_repo['timestamp'] > $existing_blueprint['timestamp']) {
                    $blueprint_from_repo['id'] = $existing_blueprint['id'];
                    $this->save($blueprint_from_repo);
                }
            } else {
                $this->create();
                $this->save($blueprint_from_repo);
            }
        }
    }

    public function getMermaidForData($workflowBlueprintData)
    {
        App::uses('MermaidFlowchartTool', 'Tools');
        $mermaid = MermaidFlowchartTool::mermaid($workflowBlueprintData);
        return $mermaid;
    }

    public function getDotNotation($id)
    {
        App::uses('GraphvizDOTTool', 'Tools');
        $blueprint = $this->find('first', [
            'conditions' => ['id' => $id],
            'recursive' => -1,
        ]);
        $dot = GraphvizDOTTool::dot($blueprint['WorkflowBlueprint']['data']);
        return $dot;
    }

    public function getMermaid($id)
    {
        App::uses('MermaidFlowchartTool', 'Tools');
        $blueprint = $this->find('first', [
            'conditions' => ['id' => $id],
            'recursive' => -1,
        ]);
        $mermaid = MermaidFlowchartTool::mermaid($blueprint['WorkflowBlueprint']['data']);
        return $mermaid;
    }
}
