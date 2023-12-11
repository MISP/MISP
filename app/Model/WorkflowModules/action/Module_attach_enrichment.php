<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_attach_enrichment extends WorkflowBaseActionModule
{
    public $id = 'attach-enrichment';
    public $name = 'Attach enrichment';
    public $version = '0.3';
    public $description = 'Attach selected enrichment result to Attributes.';
    public $icon = 'asterisk';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Module;
    private $allModulesByName = [];


    public function __construct()
    {
        parent::__construct();
        $this->Module = ClassRegistry::init('Module');
        $modules = $this->Module->getModules('Enrichment');
        if (is_array($modules)) {
            $this->allModulesByName = Hash::combine($modules, '{n}.name', '{n}');
        }
        $moduleOptions = [];
        $pickerOptions = [];
        $enrichmentAvailable = false;
        if (!empty($modules) && is_array($modules)) {
            $enrichmentAvailable = true;
            $moduleOptions = array_merge([''], Hash::combine($modules, '{n}.name', '{n}.name'));
        } else {
            $pickerOptions = [
                'placeholder_text_multiple' => __('No enrichment module available'),
            ];
        }
        sort($moduleOptions);
        $this->params = [
            [
                'id' => 'modules',
                'label' => 'Modules',
                'type' => 'picker',
                'multiple' => true,
                'disabled' => !$enrichmentAvailable,
                'options' => $moduleOptions,
                'picker_options' => $pickerOptions,
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['modules']['value'])) {
            $errors[] = __('No enrichmnent module selected');
            return false;
        } else if (is_string($params['modules']['value'])) {
            $params['modules']['value'] = [$params['modules']['value']];
        }
        $selectedModules = array_filter($params['modules']['value'], function($module) {
            return $module !== '';
        });
        $event_id = $rData['Event']['id'];
        $options = [
            'user' => $roamingData->getUser(),
            'event_id' => $event_id,
        ];

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false) {
            return true;
        }
        $this->_buildFastLookupForRoamingData($rData);

        foreach ($matchingItems as $attribute) {
            foreach ($selectedModules as $selectedModule) {
                $moduleConfig = $this->allModulesByName[$selectedModule];
                $moduleData = $options;
                $moduleData['config'] = $this->getModuleOptions($moduleConfig);
                $moduleData['module'] = $selectedModule;
                $moduleData['attribute'] = $attribute;
                if (!$this->_checkIfInputSupported($attribute, $moduleConfig)) { // Queried module doesn't support the Attribute's type
                    continue;
                }
                if (empty($moduleConfig['mispattributes']['format'])) { // Adapt payload if modules doesn't support the misp-format
                    $moduleData = $this->_convertPayloadToModuleFormat($moduleData, $moduleConfig);
                }
                $queryResult = $this->_queryModules($moduleData, $attribute, $rData);
                $queryResult = $this->_handleModuleResult($queryResult, $moduleConfig);
                $rData = $this->_attachEnrichmentData($attribute, $queryResult, $rData);
            }
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

    protected function _convertPayloadToModuleFormat(array $options, array $moduleConfig): array
    {
        $attribute = $options['attribute'];
        unset($options['attribute']);
        foreach ($moduleConfig['mispattributes']['input'] as $supportedAttributeType) {
            if ($supportedAttributeType == $attribute['type']) {
                $options[$supportedAttributeType] = $attribute['value'];
            }
        }
        return $options;
    }

    protected function _checkIfInputSupported(array $attribute, array $moduleConfig): bool
    {
        foreach ($moduleConfig['mispattributes']['input'] as $supportedAttributeType) {
            if ($supportedAttributeType == $attribute['type']) {
                return true;
            }
        }
        return false;
    }

    protected function _handleModuleResult(array $queryResult, array $moduleConfig): array
    {
        return $queryResult;
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

    protected function getModuleOptions(array $moduleConfig): array
    {
        $type = 'Enrichment';
        $options = [];
        if (isset($moduleConfig['meta']['config'])) {
            foreach ($moduleConfig['meta']['config'] as $conf) {
                $options[$conf] = Configure::read('Plugin.' . $type . '_' . $moduleConfig['name'] . '_' . $conf);
            }
        }
        return !empty($options) ? $options : ['_' => '_']; // avoid casting empty associative array in to empty list
    }
}
