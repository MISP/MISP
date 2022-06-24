<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_user_edit extends WorkflowBaseTriggerModule
{
    public $id = 'user-edit';
    public $name = 'User Edit';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'user-edit';
    public $inputs = 0;
    public $outputs = 1;

    public function __construct()
    {
        parent::__construct();
    }
}
