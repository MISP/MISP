<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_misp_module extends WorkflowBaseModule
{
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
        $this->id = Inflector::tableize($misp_module_config['name']);
        $this->name = $misp_module_config['name'];
        $this->description = $misp_module_config['meta']['description'];
        if (!empty($misp_module_config['meta']['icon'])) {
            $this->icon = $misp_module_config['meta']['icon'];
        }
        $this->icon_class = $misp_module_config['meta']['icon_class'] ?? '';
        if (!empty($misp_module_config['meta']['inputs'])) {
            $this->inputs = (int)$misp_module_config['meta']['inputs'];
        }
        if (!empty($misp_module_config['meta']['outputs'])) {
            $this->inputs = (int)$misp_module_config['meta']['outputs'];
        }
        if (!empty($misp_module_config['meta']['config'])) {
            $this->params = $misp_module_config['meta']['config'];
        }
        $this->Module = ClassRegistry::init('Module');
    }

    public function exec(array $node)
    {
        $postData = ['post-data' => 'test'];
        $result = $this->Module->queryModuleServer($postData, false, 'Action', false);
        if (!empty($result['error'])) {
        }
        return $result;
    }
}
