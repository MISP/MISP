<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_attach_enrichment extends WorkflowBaseActionModule
{
    public $id = 'attach-enrichment';
    public $name = 'Attach enrichment';
    public $description = 'Attach selected enrichment result to Attributes.';
    public $icon = 'asterisk';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Module;
    private $fastLookupArrayMispFormat = [];
    private $fastLookupArrayFlattened = [];


    public function __construct()
    {
        parent::__construct();
        $this->Module = ClassRegistry::init('Module');
        $modules = $this->Module->getModules('Enrichment');
        $moduleOptions = [];
        if (is_array($modules)) {
            $moduleOptions = array_merge([''], Hash::combine($modules, '{n}.name', '{n}.name'));
        } else {
            $moduleOptions[] = $modules;
        }
        sort($moduleOptions);
        $this->params = [
            [
                'id' => 'modules',
                'label' => 'Modules',
                'type' => 'select',
                'options' => $moduleOptions,
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);
        if (empty($params['modules']['value'])) {
            $errors[] = __('No enrichmnent module selected');
            return false;
        }
        $rData = $roamingData->getData();
        $event_id = $rData['Event']['id'];
        $options = [
            'user' => $roamingData->getUser(),
            'event_id' => $event_id,
            'module' => $params['modules']['value'],
            'config' => ['_' => '_'], // avoid casting empty associative array in to empty list
        ];

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false) {
            return true;
        }
        $this->_buildFastLookupForRoamingData($rData);

        foreach ($matchingItems as $attribute) {
            $moduleData = $options;
            $moduleData['attribute'] = $attribute;
            $queryResult = $this->_queryModules($moduleData, $attribute, $rData);
            $rData = $this->_attachEnrichmentData($attribute, $queryResult, $rData);
        }
        $roamingData->setData($rData);
        return true;
    }

    protected function _queryModules(array $moduleData, array $attribute, array $rData): array
    {
        $result = $this->Module->queryModuleServer($moduleData, true, 'Enrichment', false, $rData);
        if (!isset($result['error'])) {
            $result = $result['results'];
        }
        return $result;
    }

    protected function _buildFastLookupForRoamingData($rData): void
    {
        foreach ($rData['Event']['Attribute'] as $i => $attribute) {
            $this->fastLookupArrayMispFormat[$attribute['id']] = $i;
        }
        foreach ($rData['Event']['Object'] as $j => $object) {
            foreach ($object['Attribute'] as $i => $attribute) {
                $this->fastLookupArrayMispFormat[$attribute['id']] = [$j, $i];
            }
        }
        foreach ($rData['Event']['_AttributeFlattened'] as $i => $attribute) {
            $this->fastLookupArrayFlattened[$attribute['id']] = $i;
        }
    }

    protected function _attachEnrichmentData(array $attribute, array $queryResult, array $rData): array
    {
        $attributeID = $attribute['id'];
        $rData['Event']['_AttributeFlattened'][$this->fastLookupArrayFlattened[$attributeID]]['enrichment'][] = $queryResult;
        if (is_array($this->fastLookupArrayMispFormat[$attributeID])) {
            $objectID = $this->fastLookupArrayMispFormat[$attributeID][0];
            $attributeID = $this->fastLookupArrayMispFormat[$attributeID][1];
            $rData['Event']['Object'][$objectID]['Attribute'][$attributeID]['enrichment'][] = $queryResult;
        } else {
            $attributeID = $this->fastLookupArrayMispFormat[$attributeID];
            $rData['Event']['Attribute'][$attributeID]['enrichment'][] = $queryResult;
        }
        return $rData;
    }
}
