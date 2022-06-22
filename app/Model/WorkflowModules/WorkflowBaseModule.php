<?php
class WorkflowBaseModule
{
    public $is_misp_module = false;
    public $is_blocking = false;
    public $id = 'to-override';
    public $name = 'to-override';
    public $version = '0.1';
    public $description = 'to-override';
    public $icon = '';
    public $icon_class = '';
    public $inputs = 0;
    public $outputs = 0;
    public $support_filters = false;
    public $saved_filters = [
        ['text' => 'selector', 'value' => ''],
        ['text' => 'value', 'value' => ''],
        ['text' => 'operator', 'value' => ''],
        ['text' => 'path', 'value' => ''],
    ];
    public $params = [];

    /** @var PubSubTool */
    private static $loadedPubSubTool;

    public function __construct()
    {
    }

    protected function getParams($node): array
    {
        $indexedParam = [];
        $nodeParam = [];
        foreach ($node['data']['params'] as $param) {
            $nodeParam[$param['label']] = $param;
        }
        foreach ($this->params as $param) {
            $param['value'] = $nodeParam[$param['label']]['value'] ?? null;
            $indexedParam[$param['label']] = $param;
        }
        return $indexedParam;
    }

    protected function getParamsWithValues($node): array
    {
        $indexedParam = $this->getParams($node);
        foreach ($indexedParam as $label => $param) {
            $indexedParam[$label]['value'] = $param['value'] ?? ($param['default'] ?? '');
        }
        return $indexedParam;
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
        // $this->push_zmq([
        //     'module' => $this->name,
        //     'data' => json_encode($roamingData->getData(), true),
        //     'timestamp' => time(),
        // ]);
        return true;
    }

    protected function push_zmq($message, $namespace='')
    {
        if (!self::$loadedPubSubTool) {
            App::uses('PubSubTool', 'Tools');
            $pubSubTool = new PubSubTool();
            $pubSubTool->initTool();
            self::$loadedPubSubTool = $pubSubTool;
        }
        $pubSubTool = self::$loadedPubSubTool;
        $pubSubTool->workflow_push($message, $namespace);
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

    protected function evaluateCondition($item, $operator, $value): bool
    {
        if ($operator == 'in') {
            return is_array($item) && in_array($value, $item);
        } elseif ($operator == 'not_in') {
            return is_array($item) && !in_array($value, $item);
        } elseif ($operator == 'equals') {
            return is_string($item) && $item == $value;
        } elseif ($operator == 'not_equals') {
            return is_string($item) &&  $item != $value;
        }
        return false;
    }

    protected function getItemsMatchingCondition($items, $value, $operator, $path)
    {
        foreach ($items as $i => $item) {
            $subItem = $this->extractData($item, $path);
            if (!$this->evaluateCondition($subItem, $operator, $value)) {
                unset($items[$i]);
            }
        }
        return $items;
    }
}