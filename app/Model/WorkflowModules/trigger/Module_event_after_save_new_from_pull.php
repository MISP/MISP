<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_after_save_new_from_pull extends WorkflowBaseTriggerModule
{
    public $id = 'event-after-save-new-from-pull';
    public $scope = 'event';
    public $name = 'Event After Save New From Pull';
    public $description = 'This trigger is called after a new Event has been saved in the database from a PULL operation. This trigger executes in place of `event-after-save-new`';
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
