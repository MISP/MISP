<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_new_attribute extends WorkflowBaseModule
{
    public $id = 'new-attribute';
    public $name = 'New Attribute';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'cube';
    public $inputs = 0;
    public $outputs = 1;

    public function __construct()
    {
        parent::__construct();
    }
}
