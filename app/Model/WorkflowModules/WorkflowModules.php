<?php

class WorkflowModules
{
    public $modules = [];
    public $moduleByID = [];

    public function __construct()
    {
        $this->modules = $this->loadModules();
        $this->moduleByID = Hash::combine($this->modules, '{n}.id', '{n}');
    }

    protected function loadModules(): array
    {
        return [];
    }

    public function getModules(): array
    {
        return $this->massageModules($this->modules);
    }

    protected function massageModules($modules): array
    {
        return $modules;
    }

    protected function getParams($node): array
    {
        $indexedParam = [];
        foreach ($node['data']['params'] as $param) {
            $indexedParam[$param['label']] = $param;
        }
        return $indexedParam;
    }

    public function executeNode(array $node, array $data=[])
    {
        $module = $this->moduleByID[$node['data']['id']];
        $this->{$module['_handler']}($node, $data);
    }
}