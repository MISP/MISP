<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_object_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'object-after-save';
    public $scope = 'object';
    public $name = 'Object After Save';
    public $description = 'This trigger is called after an Object has been saved in the database';
    public $icon = 'cubes';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;

    public function __construct()
    {
        parent::__construct();
    }
}
