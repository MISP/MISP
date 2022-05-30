<?php
class WorkflowBaseModule
{
    public $id = 'to-override';
    public $name = 'to-override';
    public $description = 'to-override';
    public $icon = '';
    public $icon_class = '';
    public $inputs = 0;
    public $outputs = 0;
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
        $this->push_zmq([
            'module' => $this->name,
            'data' => json_encode($roamingData->getData(), true),
            'timestamp' => time(),
        ]);
        return true;
    }

    public function push_zmq($message, $namespace='')
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

    public function logError($message)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry('SYSTEM', 'exec_module', 'Workflow', $this->id, $message);
    }

    public function checkLoading()
    {
        return 'The Factory Must Grow';
    }
}