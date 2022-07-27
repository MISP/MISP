<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'event-after-save';
    public $scope = 'event';
    public $name = 'Event After Save';
    public $description = 'This trigger is called after an Event has been saved in the database';
    public $icon = 'envelope';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_MEDIUM;

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time an Event has been saved. Generally, the performance impact of running the workflow is low but in some cases (e.g. Very active community or frequent synchronisations) it can introduce a slight slowdown of the instance.');
    }
}
