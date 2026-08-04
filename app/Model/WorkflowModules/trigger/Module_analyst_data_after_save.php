<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_analyst_data_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'analyst-data-after-save';
    public $scope = 'analyst-data';
    public $name = 'Analyst Data After Save';
    public $description = 'This trigger is called after an Analyst Data has been saved in the database';
    public $icon = 'sticky-note';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_LOW;

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time an Analyst Data has been saved.');
    }

    public function normalizeData(array $data)
    {
        $AnalystData = ClassRegistry::init('AnalystData');
        $currentType = array_key_first($data);
        $analystObjectType = $data[$currentType]['object_type'];
        $analystObjectUUID = $data[$currentType]['object_uuid'];

        if (!in_array($currentType, $AnalystData::ANALYST_DATA_TYPES)) {
            return false;
        }

        // We are missing anything related to the event/object/attribute.
        if ($analystObjectType == 'Event') {
            return $this->normalizeForEvent($data, $currentType, $analystObjectUUID);
        } else if ($analystObjectType == 'Attribute') {
            return $this->normalizeForAttribute($data, $currentType, $analystObjectUUID);
        } else if ($analystObjectType == 'Object') {
            return $this->normalizeForObject($data, $currentType, $analystObjectUUID);
        } else if ($analystObjectType == 'EventReport') {
            return $this->normalizeForEventReport($data, $currentType, $analystObjectUUID);
        }
        return false;
    }

    private function normalizeForEvent($analystData, $currentType, $uuid): array | false
    {
        $Event = ClassRegistry::init('Event');

        $event = $Event->find('first', [
            'recursive' => -1,
            'conditions' => ['Event.uuid' => $uuid],
            'contain' => [
                'Orgc' => [
                    'fields' => ['Orgc.id', 'Orgc.uuid', 'Orgc.name']
                ],
                'EventTag' => [
                    'Tag' => ['fields' => ['Tag.id', 'Tag.name', 'Tag.colour', 'Tag.exportable']]
                ]
            ]
        ]);

        if (empty($event)) {
            return false;
        }
        $event['Event'][$currentType] = [$analystData[$currentType]];

        $event = parent::normalizeData($event);
        return $event;
    }

    private function normalizeForAttribute($analystData, $currentType, $uuid): array | false
    {
        $MispAttribute = ClassRegistry::init('MispAttribute');

        $attribute = $MispAttribute->find('first', [
            'recursive' => -1,
            'conditions' => ['Attribute.uuid' => $uuid],
        ]);
        if (empty($attribute)) {
            return false;
        }

        return $this->fetchEventAndConvert($analystData, $currentType, $attribute['Attribute']['event_id']);
    }

    private function normalizeForObject($analystData, $currentType, $uuid): array | false
    {
        $Object = ClassRegistry::init('Object');

        $object = $Object->find('first', [
            'recursive' => -1,
            'conditions' => ['Attribute.uuid' => $uuid],
        ]);
        if (empty($object)) {
            return false;
        }

        return $this->fetchEventAndConvert($analystData, $currentType, $object['Object']['event_id']);
    }

    private function normalizeForEventReport($analystData, $currentType, $uuid): array | false
    {
        $EventReport = ClassRegistry::init('EventReport');

        $report = $EventReport->find('first', [
            'recursive' => -1,
            'conditions' => ['EventReport.uuid' => $uuid],
        ]);
        if (empty($report)) {
            return false;
        }

        return $this->fetchEventAndConvert($analystData, $currentType, $report['EventReport']['event_id']);
    }

    private function fetchEventAndConvert($analystData, $currentType, $event_id): array
    {
        $Event = ClassRegistry::init('Event');

        $event = $Event->quickFetchEvent($event_id);
        $event['Event'][$currentType] = [$analystData[$currentType]];

        $event = parent::normalizeData($event);
        return $event;
    }
}
