<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_add_eventblocklist_entry extends WorkflowBaseActionModule
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'add_eventblocklist_entry';
    public $name = 'Add Event Blocklist entry';
    public $description = 'Create a new entry in the Event blocklist table';
    public $icon = 'ban';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = false;
    public $expect_misp_core_format = true;
    public $params = [];

    private $EventBlocklist;
    private $Organisation;


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'uuid_hash_path',
                'label' => 'Event UUID Hash path',
                'type' => 'hashpath',
                'placeholder' => 'Event.uuid',
                'default' => 'Event.uuid',
                'hashpath' => [
                    'is_sub_selector' => true
                ]
            ],
            [
                'id' => 'eventinfo_hash_path',
                'label' => 'Event Info Hash path',
                'type' => 'hashpath',
                'placeholder' => 'Event.info',
                'default' => 'Event.info',
                'hashpath' => [
                    'is_sub_selector' => true
                ]
            ],
            [
                'id' => 'block_comment',
                'label' => 'Blocklist Comment',
                'type' => 'input',
                'placeholder' => 'Blocked from workflow',
                'default' => 'Blocked from workflow',
            ],
        ];

        $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
        $this->Organisation = ClassRegistry::init('Organisation');
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);

        $eventUUIDExtractionPath = $params['uuid_hash_path']['value'];
        $eventUUID = Hash::get($rData, $eventUUIDExtractionPath);
        $eventInfoExtractionPath = $params['eventinfo_hash_path']['value'];
        $eventInfo = Hash::get($rData, $eventInfoExtractionPath);
        $comment = $params['block_comment']['value'];

        $org = $this->Organisation->find('first', ['conditions' => array('Organisation.id' => $rData['Event']['orgc_id']), 'recursive' => -1, 'fields' => ['Organisation.name']]);
        $entry = [
            'event_uuid' => $eventUUID,
            'event_info' => $eventInfo,
            'event_orgc' => !empty($org['Organisation']['name']) ? $org['Organisation']['name'] : 'unkwown',
            'comment' => $comment,
        ];
        $r = $this->EventBlocklist->addEntry($entry);
        return true;
    }
}
