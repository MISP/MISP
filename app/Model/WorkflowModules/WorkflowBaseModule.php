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

    private $Event;

    /** @var PubSubTool */
    private static $loadedPubSubTool;

    public function __construct()
    {
    }

    protected function mergeNodeConfigIntoParameters($node): array
    {
        $fullIndexedParams = [];
        foreach ($this->params as $param) {
            $param['value'] = $nodeParamByID[$param['id']]['value'] ?? null;
            $param['value'] = $node['data']['indexed_params'][$param['id']] ?? null;
            $fullIndexedParams[$param['id']] = $param;
        }
        return $fullIndexedParams;
    }

    protected function getParamsWithValues($node): array
    {
        $indexedParams = $this->mergeNodeConfigIntoParameters($node);
        foreach ($indexedParams as $id => $param) {
            $indexedParams[$id]['value'] = $param['value'] ?? ($param['default'] ?? '');
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

    protected function logError($message)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry('SYSTEM', 'exec_module', 'Workflow', $this->id, $message);
    }

    public function checkLoading()
    {
        return 'The Factory Must Grow';
    }

    protected function extractData($data, $path)
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
                return array_values($matching) == array_values($value);
            } elseif ($operator == 'not_in_or') {
                return empty($matching);
            } elseif ($operator == 'not_in_and') {
                return array_values($matching) != array_values($value);
            }
        }
        return false;
    }

    protected function getItemsMatchingCondition($items, $value, $operator, $path)
    {
        foreach ($items as $i => $item) {
            $subItem = $this->extractData($item, $path, $operator);
            if (in_array($operator, ['equals', 'not_equals'])) {
                $subItem = !empty($subItem) ? $subItem[0] : $subItem;
            }
            if (!$this->evaluateCondition($subItem, $operator, $value)) {
                unset($items[$i]);
            }
        }
        return $items;
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
}
