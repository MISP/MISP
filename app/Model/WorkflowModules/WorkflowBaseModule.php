<?php
class WorkflowBaseModule
{
    public $is_misp_module = false;
    public $blocking = false;
    public $is_custom = false;
    public $expect_misp_core_format = false;
    public $id = 'to-override';
    public $name = 'Ad-Hoc';
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
                $rDataWithEnv = $rData;
                $rDataWithEnv['_env'] = [
                    'baseurl' => Configure::read('MISP.baseurl'),
                ];
                $indexedParams[$id]['value'] = $this->render_jinja_template($param['value'], $rDataWithEnv);
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
        if (!empty($result['error']) || $result === false) {
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
        return array_values($items);
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

    public function reloadRoamingData(WorkflowRoamingData $roamingData): void
    {
        // Impossible to reload roaming if not in known format
        if ($this->expect_misp_core_format) {
            $this->Event = ClassRegistry::init('Event');
            $event = $roamingData->getData();
            $fullEvent = $this->Event->fetchEvent($roamingData->getUser(), [
                'eventid' => $event['Event']['id'],
                'includeAttachments' => 1
            ]);
            App::uses('WorkflowFormatConverterTool', 'Tools');
            $fullEvent = WorkflowFormatConverterTool::convert($fullEvent[0]);
            if (!empty($fullEvent)) {
                $roamingData->setData($fullEvent);;
            }
        }
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

class AdHocTrigger extends WorkflowBaseTriggerModule
{
    public $id = 'adhoc-trigger';
    public $icon = 'hand-pointer';
    public $description = "Ad-Hoc trigger to be called manually";
    public $is_adhoc = true;
    public $blocking = true;
    public $misp_core_format = true;
    public $is_misp_module = false;
    public $is_custom = false;
    public $params = [];

    private $Event;
    private $Attribute;
    private $EventReport;

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'scope',
                'label' => __('Data Input Scope'),
                'type' => 'select',
                'default' => 'events',
                'options' => [
                    'passed_roaming_data' => 'Passed Roaming Data',
                    'passed_event_ids' => 'Passed Event IDs',
                    'events' => 'Events RestSearch',
                    // 'attributes' => 'Attributes RestSearch',
                    // 'event_reports' => 'Event Reports RestSearch',
                ],
            ],
            [
                'id' => 'filters',
                'label' => __('Search Filters'),
                'type' => 'textarea',
                'default' => '{}',
                'placeholder' => '{
    "publish_timestamp": "24h"
}',
                'jinja_supported' => true,
                'display_on' => [
                    'scope' => ['events', 'attributes'],
                ],
            ],
        ];
    }

    public function collectData(array $user, array $indexed_params, array $passedFilters = []): array
    {
        $scope = $indexed_params['scope'];
        $filters = $indexed_params['filters'];
        $filters = JsonTool::decode($filters);

        if ($scope == 'passed_roaming_data') {
            return [$passedFilters];
        } else if ($scope == 'passed_event_ids') {
            return $this->getEventFromPassedFilters($user, $passedFilters);
        } else if ($scope == 'events') {
            return $this->getEvents($user, $filters);
        } else if ($scope == 'attributes') {
            return []; // TODO: Ensure it works correctly before allowing user to use this scope
            return $this->getAttributes($user, $filters);
        } else if ($scope == 'event_reports') {
            return []; // TODO: Ensure it works correctly before allowing user to use this scope
            return $this->getEventReports($user, $filters);
        } else {
            return [];
        }
    }

    private function getEventFromPassedFilters(array $user, array $passedFilters = []): array
    {
        $this->Event = ClassRegistry::init('Event');
        if (!empty($passedFilters['Event'])) {
            return []; // Passed filter is an Event and not restSearch filters
        }
        $final = $this->Event->restSearch($user, 'json', $passedFilters);
        return JsonTool::decode($final->intoString())['response'];
    }
    private function getEvents(array $user, array $filters): array
    {
        $this->Event = ClassRegistry::init('Event');
        $final = $this->Event->restSearch($user, 'json', $filters);
        return JsonTool::decode($final->intoString())['response'];
    }
    private function getAttributes(array $user, array $filters): array
    {
        $this->Attribute = ClassRegistry::init('Attribute');
        $final = $this->Attribute->restSearch($user, 'json', $filters);
        return JsonTool::decode($final->intoString())['response'];
    }
    private function getEventReports(array $user, array $filters): array
    {
        $this->EventReport = ClassRegistry::init('EventReport');
        $final = $this->EventReport->restSearch($user, 'json', $filters);
        return JsonTool::decode($final->intoString())['response'];
    }

    public function normalizeData(array $data)
    {
        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('Attribute');
        $this->EventReport = ClassRegistry::init('EventReport');

        $event = parent::normalizeData($data);
        return $event;
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
    public $isFiltering = false;
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