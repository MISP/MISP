<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_attribute_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'attribute-after-save';
    public $scope = 'attribute';
    public $name = 'Attribute After Save';
    public $description = 'This trigger is called after an Attribute has been saved in the database';
    public $icon = 'cube';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;

    public function __construct()
    {
        parent::__construct();
    }
}
