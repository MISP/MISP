<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_sighting_publish extends WorkflowBaseTriggerModule
{
    public $id = 'sighting-publish';
    public $scope = 'sighting';
    public $name = 'Sighting Publish';
    public $description = 'This trigger is called when a sighting has been published';
    public $icon = 'eye';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = false;
    public $trigger_overhead = self::OVERHEAD_HIGH;

    public function __construct()
    {
        parent::__construct();
    }
}
