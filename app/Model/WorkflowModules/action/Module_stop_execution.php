<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_stop_execution extends WorkflowBaseActionModule
{
    public $blocking = true;
    public $id = 'stop-execution';
    public $name = 'Stop execution';
    public $description = 'Essentially stops the execution for blocking workflows. Do nothing for non-blocking ones';
    public $icon = 'ban';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];

    public function __construct()
    {
        parent::__construct();
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $errors[] = __('Execution stopped');
        return false;
    }
}
