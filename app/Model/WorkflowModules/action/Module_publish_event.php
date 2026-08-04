<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_publish_event extends WorkflowBaseActionModule
{
    public $id = 'publish-event';
    public $name = 'Publish Event';
    public $version = '0.1';
    public $description = 'Publish an Event in the context of the workflow';
    public $icon = 'upload';
    public $inputs = 1;
    public $outputs = 1;
    public $params = [];

    private $Event;


    public function __construct()
    {
        parent::__construct();
        $this->Event = ClassRegistry::init('Event');
        $this->params = [
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        $rData = $roamingData->getData();
        $event_id = $rData['Event']['id'];
        $result = $this->Event->publish($event_id, null);
        return $result === true;
    }
}
