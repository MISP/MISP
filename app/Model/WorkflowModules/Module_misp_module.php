<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_misp_module extends WorkflowBaseModule
{
    public $is_blocking = false;
    public $is_misp_module = true;
    public $id = 'misp-module';
    public $name = 'misp-module';
    public $description = 'misp-module';
    public $icon = 'python';
    public $icon_class = 'fab';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];

    /** @var Module */
    private $Module;
    private $misp_module_config;

    public function __construct($misp_module_config)
    {
        parent::__construct();
        $this->id = Inflector::underscore($misp_module_config['name']);
        $this->name = $misp_module_config['name'];
        $this->description = $misp_module_config['meta']['description'];
        if (!empty($misp_module_config['meta']['icon'])) {
            $this->icon = $misp_module_config['meta']['icon'];
        }
        if (!empty($misp_module_config['meta']['icon_class'])) {
            $this->icon_class = $misp_module_config['meta']['icon_class'];
        }
        if (!empty($misp_module_config['meta']['inputs'])) {
            $this->inputs = (int)$misp_module_config['meta']['inputs'];
        }
        if (!empty($misp_module_config['meta']['outputs'])) {
            $this->inputs = (int)$misp_module_config['meta']['outputs'];
        }
        if (!empty($misp_module_config['mispattributes']['blocking'])) {
            $this->is_blocking = !empty($misp_module_config['mispattributes']['blocking']);
        }
        if (!empty($misp_module_config['meta']['config'])) {
            foreach ($misp_module_config['meta']['config'] as $paramName => $moduleParam) {
                $this->params[] = $this->translateParams($paramName, $moduleParam);
            }
        }
        $this->Module = ClassRegistry::init('Module');
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData);
        $postData = ['module' => $this->name];
        $postData['data'] = $roamingData->getData();
        $query = $this->Module->queryModuleServer($postData, false, 'Action', false, $postData['data']);
        if (!empty($query['error'])) {
            $errors[] = $query['error'];
            return false;
        }
        $message = [
            "module:$this->name" => JsonTool::encode($query['data'])
        ];
        $this->push_zmq($message);
        return true;
    }

    // FIXME: We might want to align the module config with what's currently supported
    protected function translateParams($paramName, $moduleParam): array
    {
        $param = [];
        $param['label'] = $paramName;
        $param['placeholder'] = $moduleParam['value'];
        $param['type'] = 'input';
        return $param;
    }
}
