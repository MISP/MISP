<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_user_before_save extends WorkflowBaseTriggerModule
{
    public $id = 'user-before-save';
    public $scope = 'user';
    public $name = 'User Before Save';
    public $description = 'This trigger is called just before a user is save in the database';
    public $icon = 'user-plus';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;
    public $trigger_overhead = self::OVERHEAD_LOW;

    public function __construct()
    {
        parent::__construct();
    }
}
