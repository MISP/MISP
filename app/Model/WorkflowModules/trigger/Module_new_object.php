<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_new_object extends WorkflowBaseModule
{
    public $id = 'new-object';
    public $name = 'New Object';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'cubes';
    public $inputs = 0;
    public $outputs = 2;

    public function __construct()
    {
        parent::__construct();
    }
}
