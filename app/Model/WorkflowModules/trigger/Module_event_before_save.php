<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_before_save extends WorkflowBaseTriggerModule
{
    public $id = 'event-before-save';
    public $scope = 'event';
    public $name = 'Event Before Save';
    public $description = 'This trigger is called before an Event or any of its elements is about to be saved in the database';
    public $icon = 'envelope';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_HIGH;

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time an Event or Attribute is about to be saved. This means that when a large quantity of Attributes are being saved (e.g. Feed pulling or synchronisation), the workflow will be run for as many time as there are Attributes.');
    }
}
