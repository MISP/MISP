<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_do_nothing extends WorkflowBaseModule
{
    public $id = 'do-nothing';
    public $name = 'Do Nothing';
    public $description = 'Essentially a /dev/null';
    public $icon = 'ban';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];


    public function __construct()
    {
        parent::__construct();
    }
}
