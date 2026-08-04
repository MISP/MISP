<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_log_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'log-after-save';
    public $scope = 'log';
    public $name = 'Log After Save';
    public $description = 'This trigger is called after a Log event has been saved in the database';
    public $icon = 'file';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $trigger_overhead = self::OVERHEAD_HIGH;

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time after Log event has been saved. This means that when a large quantity of Logs are being saved, the workflow will be run for as many time as there are log entries.');
    }
}
