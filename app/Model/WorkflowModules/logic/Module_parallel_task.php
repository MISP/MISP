<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_parallel_task extends WorkflowBaseModule
{
    public $id = 'parallel-task';
    public $name = 'Parallel Task';
    public $description = 'Allow breaking the execution process and running parallel tasks. You can connect multiple blocks the `parallel` output.';
    public $icon = 'random';
    public $inputs = 1;
    public $outputs = 1;
    public $html_template = 'parallel';
    public $params = [];

    public function __construct()
    {
        parent::__construct();
    }
}
