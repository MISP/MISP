<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_new_user extends WorkflowBaseModule
{
    public $id = 'new-user';
    public $name = 'New User';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'user-plus';
    public $inputs = 0;
    public $outputs = 1;

    public function __construct()
    {
        parent::__construct();
    }
}
