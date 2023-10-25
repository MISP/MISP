<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_misp_module extends WorkflowBaseActionModule
{
    public $blocking = false;
    public $is_misp_module = true;
    public $id = 'misp-module';
    public $name = 'misp-module';
    public $description = 'misp-module';
    public $icon = 'python';
    public $icon_class = 'fab';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = false;
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
        if (!empty($misp_module_config['meta']['config']['blocking'])) {
            $this->blocking = !empty($misp_module_config['meta']['config']['blocking']);
        }
        if (!empty($misp_module_config['meta']['config']['expect_misp_core_format'])) {
            $this->expect_misp_core_format = !empty($misp_module_config['meta']['config']['expect_misp_core_format']);
        }
        if (!empty($misp_module_config['meta']['config']['support_filters'])) {
            $this->support_filters = !empty($misp_module_config['meta']['config']['support_filters']);
        }
        if (!empty($misp_module_config['meta']['config']['params'])) {
            foreach ($misp_module_config['meta']['config']['params'] as $paramName => $moduleParam) {
                $this->params[] = $this->translateParams($paramName, $moduleParam);
            }
        }
        $this->Module = ClassRegistry::init('Module');
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData);
        $postData = ['module' => $this->name];
        $rData = $roamingData->getData();
        $postData['data'] = $rData;
        if ($this->support_filters) {
            $filters = $this->getFilters($node);
            $extracted = $this->extractData($rData, $filters['selector']);
            if ($extracted === false) {
                return false;
            }
            $filteredItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
            $postData['filteredItems'] = !empty($filteredItems) ? $filteredItems : $rData;
        }

        $rData = $roamingData->getData();
        $indexedParams = $this->getParamsWithValues($node, $rData);
        $postData['params'] = Hash::combine($indexedParams, '{s}.id', '{s}.value');
        $matchingData = [];
        foreach ($indexedParams as $param) {
            if (!empty($param['_isHashPath'])) {
                $matchingData[$param['label']] = !empty($param['value']) ? $this->extractData($rData, $param['value']) : $rData;
            }
        }
        if (!empty($matchingData)) {
            $postData['matchingData'] = $matchingData;
        }

        $query = $this->Module->queryModuleServer($postData, false, 'Action', false, $postData['data']);
        if (!empty($query['error'])) {
            $errors[] = $query['error'];
            return false;
        }
        return true;
    }

    // FIXME: We might want to align the module config with what's currently supported
    protected function translateParams($paramName, $moduleParam): array
    {
        $param = [
            'id' => Inflector::slug(Inflector::underscore($paramName)),
            'label' => Inflector::humanize($paramName),
            'placeholder' => $moduleParam['value'] ?? '',
        ];
        if ($moduleParam['type'] == 'hash_path') {
            $param['type'] = 'input';
            $param['_isHashPath'] = true;
        } elseif ($moduleParam['type'] == 'large_string') {
            $param['type'] = 'textarea';
        } else {
            $param['type'] = 'input';
        }
        if (isset($moduleParam['jinja_supported'])) {
            $param['jinja_supported'] = !empty($moduleParam['jinja_supported']);
        }
        return $param;
    }
}
