<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_publish extends WorkflowBaseTriggerModule
{
    public $id = 'publish';
    public $name = 'Publish';
    public $description = 'This trigger is called just before a MISP event starts the publishing process';
    public $icon = 'upload';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;
    public $misp_core_format = true;

    public function __construct()
    {
        parent::__construct();
    }
}