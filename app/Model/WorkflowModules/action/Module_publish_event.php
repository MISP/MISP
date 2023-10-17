<?php
include_once APP . 'Model/WorkflowModules/action/Module_webhook.php';

class Module_publish_event extends Module_webhook
{
    public $id = 'publish-event';
    public $name = 'Publish Event';
    public $version = '0.1';
    public $description = 'Publish an Event in the context of the workflow';
    public $icon_path = 'upload';

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
        $result = $this->Event->publish($event_id, null);
        return $result === true;
    }
}
