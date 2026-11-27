<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_after_save_new extends WorkflowBaseTriggerModule
{
    public $id = 'event-after-save-new';
    public $scope = 'event';
    public $name = 'Event After Save New';
    public $description = 'This trigger is called after a new Event has been saved in the database. Events added by a pull or a feed fetch call `event-after-save-new-from-pull` instead.';
    public $icon = 'envelope';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_LOW;

    public function __construct()
    {
        parent::__construct();
    }
}
