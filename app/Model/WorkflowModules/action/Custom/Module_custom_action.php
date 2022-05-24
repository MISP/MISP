<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_custom_action extends WorkflowBaseModule
{
    public $id = 'custom-action';
    public $name = 'User-defined Module';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'hand-point-up';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];

    public function __construct()
    {
        parent::__construct();
    }
}
