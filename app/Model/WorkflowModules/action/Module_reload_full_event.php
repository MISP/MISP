<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_reload_full_event extends WorkflowBaseActionModule
{
    public $id = 'reload-full-event';
    public $name = 'Reload full Event';
    public $version = '0.1';
    public $description = 'Reload the full Event from the database and assign it to the roaming data.';
    public $icon = 'sync-alt';
    public $inputs = 1;
    public $outputs = 1;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Module;


    public function __construct()
    {
        parent::__construct();
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $triggerNode = $roamingData->getTriggerNode();

        if (!empty($triggerNode['data']['misp_core_format'])) {
            $this->reloadRoamingData($roamingData);
        }
        return true;
    }
}
