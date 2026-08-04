<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_sighting_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'sighting-after-save';
    public $scope = 'sighting';
    public $name = 'Sighting After Save';
    public $description = 'This trigger is called when a sighting has been saved';
    public $icon = 'eye';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_MEDIUM;

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time a Sighting has been saved. This means that when a large quantity of Sightings are being saved (e.g. Feed pulling or synchronisation), the workflow will be run for as many time as there are Sightings.');
    }


    public function normalizeData(array $data)
    {
        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('MispAttribute');

        if (empty($data['Sighting'])) {
            return false;
        }

        // We are missing data such as tags or objects.
        $event = $this->Event->quickFetchEvent($data['Sighting']['Event']['id']);
        $attribute = $this->Attribute->fetchAttribute($data['Sighting']['Attribute']['id']);

        if (!empty($attribute['Object'])) {
            $event['Event']['Object'] = [$attribute['Object']];
            $event['Event']['Object'][0]['Attribute'] = [$attribute['Attribute']];
        } else {
            $event['Event']['Attribute'] = [$attribute['Attribute']];
        }

        $event = parent::normalizeData($event);
        return $event;
    }
}
