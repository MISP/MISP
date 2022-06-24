<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_user_add extends WorkflowBaseTriggerModule
{
    public $id = 'user-add';
    public $name = 'User Add';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'user-plus';
    public $inputs = 0;
    public $outputs = 1;

    public function __construct()
    {
        parent::__construct();
    }
}
