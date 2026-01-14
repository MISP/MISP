<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_before_delete extends WorkflowBaseTriggerModule
{
    public $id = 'event-before-delete';
    public $scope = 'event';
    public $name = 'Event Before Delete';
    public $description = 'This trigger is called before an Event is about to be deleted from the database';
    public $icon = 'trash';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_LOW;

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time an Event is about to be deleted, which shouldn\'t happen that frequently.');
    }
}
