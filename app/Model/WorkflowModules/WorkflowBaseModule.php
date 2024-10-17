<?php
class WorkflowBaseModule
{
    public $is_misp_module = false;
    public $blocking = false;
    public $is_custom = false;
    public $expect_misp_core_format = false;
    public $id = 'to-override';
    public $name = 'to-override';
    public $version = '0.1';
    public $description = 'to-override';
    public $icon = '';
    public $icon_class = '';
    public $inputs = 0;
    public $outputs = 0;
    public $multiple_output_connection = false;
    public $support_filters = false;
    public $saved_filters = [
        ['text' => 'selector', 'value' => ''],
        ['text' => 'value', 'value' => ''],
        ['text' => 'operator', 'value' => ''],
        ['text' => 'path', 'value' => ''],
    ];
    public $params = [];

    private $Workflow;

    /** @var PubSubTool */
    private static $loadedPubSubTool;

    public function __construct()
    {
    }

    public function debug(array $node, WorkflowRoamingData $roamingData, array $data=[]): void
    {
        if (!isset($this->Workflow)) {
            $this->Workflow = ClassRegistry::init('Workflow');
        }
        $workflow = $roamingData->getWorkflow();
        $path = sprintf('/debug/%s', $node['data']['id'] ?? '');
        $this->Workflow->sendRequestToDebugEndpoint($workflow, $node, $path, $data);
    }

    protected function mergeNodeConfigIntoParameters($node): array
    {
        $fullIndexedParams = [];
        foreach ($this->params as $param) {
            $param['value'] = $node['data']['indexed_params'][$param['id']] ?? null;
            $fullIndexedParams[$param['id']] = $param;
        }
        return $fullIndexedParams;
    }

    protected function getParamsWithValues(array $node, array $rData): array
    {
        $indexedParams = $this->mergeNodeConfigIntoParameters($node);
        foreach ($indexedParams as $id => $param) {
            $indexedParams[$id]['value'] = $param['value'] ?? ($param['default'] ?? '');
            if (!empty($param['jinja_supported']) && strlen($param['value']) > 0) {
                $indexedParams[$id]['value'] = $this->render_jinja_template($param['value'], $rData);
            }
        }
        return $indexedParams;
    }

    protected function filtersEnabled($node): bool
    {
        $indexedFilters = $this->getFilters($node);
        foreach ($indexedFilters as $k => $v) {
            if ($v != '') {
                return true;
            }
        }
        return false;
    }

    protected function getFilters($node): array
    {
        $indexedFilters = [];
        $nodeParam = [];
        foreach ($node['data']['saved_filters'] as $name => $value) {
            $nodeParam[$name] = $value;
        }
        foreach ($this->saved_filters as $filter) {
            $filter['value'] = $nodeParam[$filter['text']] ?? $filter['value'];
            $indexedFilters[$filter['text']] = $filter['value'];
        }
        return $indexedFilters;
    }

    public function getConfig(): array
    {
        $reflection = new ReflectionObject($this);
        $properties = [];
        foreach ($reflection->getProperties() as $property) {
            if ($property->isPublic()) {
                $properties[$property->getName()] = $property->getValue($this);
            }
        }
        return $properties;
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        return true;
    }

    protected function push_zmq($message)
    {
        if (!self::$loadedPubSubTool) {
            App::uses('PubSubTool', 'Tools');
            $pubSubTool = new PubSubTool();
            $pubSubTool->initTool();
            self::$loadedPubSubTool = $pubSubTool;
        }
        $pubSubTool = self::$loadedPubSubTool;
        $pubSubTool->workflow_push($message);
    }

    protected function render_jinja_template($template, array $data): string
    {
        $mispModule = ClassRegistry::init('Module');
        $postData = [
            'module' => 'jinja_template_rendering',
            'text' => JsonTool::encode([
                'template' => $template,
                'data' => $data,
            ])
        ];
        $result = $mispModule->queryModuleServer($postData, false, 'Enrichment', false, [], true);
        if (!empty($result['error'])) {
            return '';
        }
        $rendered = $result['results'][0]['values'][0];
        return $rendered;
    }

    protected function logError($message)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry('SYSTEM', 'exec_module', 'Workflow', $this->id, $message);
    }

    public function checkLoading()
    {
        return 'The Factory Must Grow';
    }

    public function extractData($data, $path)
    {
        $extracted = $data;
        if (!empty($path)) {
            try {
                $extracted = Hash::extract($data, $path);
            } catch (Exception $e) {
                return false;
            }
        }
        return $extracted;
    }

    protected function getMatchingItemsForAttributes(array $node, array $rData): array
    {
        if ($this->filtersEnabled($node)) {
            $filters = $this->getFilters($node);
            $extracted = $this->extractData($rData, $filters['selector']);
            if ($extracted === false) {
                return false;
            }
            $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        } else {
            $matchingItems = Hash::extract($rData, 'Event._AttributeFlattened.{n}');
        }
        return $matchingItems;
    }

    protected function extractDataForFilters(array $node, WorkflowRoamingData $roamingData)
    {
        $rData = $roamingData->getData();
        if (empty($this->support_filters)) {
            return $rData;
        }
        $filters = $this->getFilters($node);
        if (in_array(null, array_values($filters))) {
            return $rData;
        }
        $extracted = $this->extractData($rData, $filters['selector']);
        if ($extracted === false) {
            return $rData;
        }
        $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        return $matchingItems;
    }

    protected function evaluateCondition($data, $operator, $value): bool
    {
        if ($operator == 'in') {
            return is_array($data) && in_array($value, $data);
        } elseif ($operator == 'not_in') {
            return is_array($data) && !in_array($value, $data);
        } elseif ($operator == 'equals') {
            return !is_array($data) && $data == $value;
        } elseif ($operator == 'not_equals') {
            return !is_array($data) && $data != $value;
        } elseif ($operator == 'in_or' || $operator == 'in_and' || $operator == 'not_in_or' || $operator == 'not_in_and') {
            if (!is_array($data) || !is_array($value)) {
                return false;
            }
            $matching = array_filter($data, function($item) use ($value) {
                return in_array($item, $value);
            });
            if ($operator == 'in_or') {
                return !empty($matching);
            } elseif ($operator == 'in_and') {
                sort($matching);
                sort($value);
                return array_values($matching) == array_values($value);
            } elseif ($operator == 'not_in_or') {
                return empty($matching);
            } elseif ($operator == 'not_in_and') {
                return array_values($matching) != array_values($value);
            }
        }
        return false;
    }

    public function getItemsMatchingCondition($items, $value, $operator, $path)
    {
        foreach ($items as $i => $item) {
            $subItem = $this->extractData($item, $path);
            if (in_array($operator, ['equals', 'not_equals'])) {
                $subItem = !empty($subItem) ? $subItem[0] : $subItem;
            }
            if ($operator == 'any_value' && !empty($subItem)) {
                continue;
            } else if (!$this->evaluateCondition($subItem, $operator, $value)) {
                unset($items[$i]);
            }
        }
        return $items;
    }

    protected function addNotification(array $errors, string $severity, string $text, string $description='', array $details=[], bool $showInSidebar=false, bool $showInNode=false): array
    {
         $errors[$severity][] = [
            'text' => $text,
            'description' => $description,
            'details' => $details,
            '__show_in_sidebar' => $showInSidebar,
            '__show_in_node' => $showInNode,
        ];
        return $errors;
    }

    public function diagnostic(): array
    {
        return [];
    }
}

class WorkflowBaseTriggerModule extends WorkflowBaseModule
{
    const OVERHEAD_LOW = 1;
    const OVERHEAD_MEDIUM = 2;
    const OVERHEAD_HIGH = 3;

    public $scope = 'others';
    public $blocking = false;
    public $misp_core_format = false;
    public $trigger_overhead = self::OVERHEAD_LOW;
    public $trigger_overhead_message = '';
    public $inputs = 0;
    public $outputs = 1;

    /**
     * normalizeData Massage the data before entering the workflow
     *
     * @param array $data
     * @return array|false
     */
    public function normalizeData(array $data)
    {
        if (!empty($this->misp_core_format)) {
            $converted = $this->convertData($data);
            if (empty($converted)) {
                return false;
            }
            return $converted;
        }
        return $data;
    }

    /**
     * convertData function
     *
     * @param array $data
     * @return array
     */
    protected function convertData(array $data): array
    {
        App::uses('WorkflowFormatConverterTool', 'Tools');
        return WorkflowFormatConverterTool::convert($data);   
    }
}

class WorkflowBaseLogicModule extends WorkflowBaseModule
{
    public $blocking = false;
    public $inputs = 1;
    public $outputs = 2;
}

class WorkflowBaseActionModule extends WorkflowBaseModule
{
    protected $fastLookupArrayMispFormat = [];
    protected $fastLookupArrayFlattened = [];

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        $rData = $roamingData->getData();
        if ($this->expect_misp_core_format) {
            $this->_buildFastLookupForRoamingData($rData);
        }
        return true;
    }

    protected function _buildFastLookupForRoamingData($rData): void
    {
        if (!empty($rData['Event']['Attribute'])) {
            foreach ($rData['Event']['Attribute'] as $i => $attribute) {
                $this->fastLookupArrayMispFormat[$attribute['id']] = $i;
            }
        }
        if (!empty($rData['Event']['Object'])) {
            foreach ($rData['Event']['Object'] as $j => $object) {
                foreach ($object['Attribute'] as $i => $attribute) {
                    $this->fastLookupArrayMispFormat[$attribute['id']] = [$j, $i];
                }
            }
        }
        foreach ($rData['Event']['_AttributeFlattened'] as $i => $attribute) {
            $this->fastLookupArrayFlattened[$attribute['id']] = $i;
        }
    }

    protected function _overrideAttribute(array $oldAttribute, array $newAttribute, array $rData): array
    {
        $attributeID = $oldAttribute['id'];
        $rData['Event']['_AttributeFlattened'][$this->fastLookupArrayFlattened[$attributeID]] = $newAttribute;
        if (is_array($this->fastLookupArrayMispFormat[$attributeID])) {
            $objectID = $this->fastLookupArrayMispFormat[$attributeID][0];
            $attributeID = $this->fastLookupArrayMispFormat[$attributeID][1];
            $rData['Event']['Object'][$objectID]['Attribute'][$attributeID] = $newAttribute;
        } else {
            $attributeID = $this->fastLookupArrayMispFormat[$attributeID];
            $rData['Event']['Attribute'][$attributeID] = $newAttribute;
        }
        return $rData;
    }
}

class WorkflowFilteringLogicModule extends WorkflowBaseLogicModule
{
    public $blocking = false;
    public $inputs = 1;
    public $outputs = 2;

    protected function _genFilteringLabels(): array
    {
        $names = ['A', 'B', 'C', 'D', 'E', 'F'];
        $labels = [];
        foreach ($names as $name) {
            $labels[$name] = __('Label %s', $name);
        }
        return $labels;
    }
}