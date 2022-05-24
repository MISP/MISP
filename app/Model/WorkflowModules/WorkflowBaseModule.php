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

    public function __construct()
    {
    }

    protected function getParams($node): array
    {
        $indexedParam = [];
        foreach ($node['data']['params'] as $param) {
            $indexedParam[$param['label']] = $param;
        }
        return $indexedParam;
    }

    public function getConfig(): array
    {
        return (array) $this;
    }

    public function exec(array $node)
    {
        return true;
    }

    public function checkLoading()
    {
        return 'The Factory Must Grow';
    }
}