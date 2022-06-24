<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_user_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'user-after-save';
    public $name = 'User After Save';
    public $description = 'This trigger is called after a user has been saved in the database';
    public $icon = 'user-edit';
    public $inputs = 0;
    public $outputs = 1;
    public $canAbort = false;

    public function __construct()
    {
        parent::__construct();
    }
}
