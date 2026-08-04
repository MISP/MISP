<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_report_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'event-report-after-save';
    public $scope = 'event-report';
    public $name = 'Event Report After Save';
    public $description = 'This trigger is called after an Event Report has been saved in the database';
    public $icon = 'file-alt';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_LOW;

    public function __construct()
    {
        parent::__construct();
    }

    public function normalizeData(array $data)
    {
        $this->Event = ClassRegistry::init('Event');

        if (empty($data['EventReport'])) {
            return false;
        }

        // We are missing data such as tags or objects.
        $event = $this->Event->quickFetchEvent($data['EventReport']['event_id']);
        $event['Event']['EventReport'] = [$data['EventReport']];

        $event = parent::normalizeData($event);
        return $event;
    }
}
