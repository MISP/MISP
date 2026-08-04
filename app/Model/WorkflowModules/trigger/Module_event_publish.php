<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_publish extends WorkflowBaseTriggerModule
{
    public $id = 'event-publish';
    public $scope = 'event';
    public $name = 'Event Publish';
    public $description = 'This trigger is called just before a MISP Event starts the publishing process';
    public $icon = 'upload';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_LOW;

    public function __construct()
    {
        parent::__construct();
    }
}
