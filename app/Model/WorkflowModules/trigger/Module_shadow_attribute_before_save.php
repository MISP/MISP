<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_shadow_attribute_before_save extends WorkflowBaseTriggerModule
{
    public $id = 'shadow-attribute-before-save';
    public $scope = 'shadow-attribute';
    public $name = 'Shadow Attribute Before Save';
    public $description = 'This trigger is called just before a Shadow Attribute is saved in the database';
    public $icon = 'comment';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_MEDIUM;

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time a Shadow Attribute is about to be saved. This means that when a large quantity of Shadow Attributes are being saved (e.g. Feed pulling or synchronisation), the workflow will be run for as many time as there are Shadow Attributes.');  
    }

    public function normalizeData(array $data)
    {
        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('Attribute');

        if (empty($data['ShadowAttribute'])) {
            return false;
        }
        
        // If we're dealing with a proposed edit, we retrieve the data about the attribute 
        if ($data['ShadowAttribute']['old_id']) {
            $event = $this->Attribute->fetchAttribute($data['ShadowAttribute']['old_id']);
            $event['Attribute']['ShadowAttribute'] = array($data['ShadowAttribute']);
        } else {
            // If it is a proposal to add a new attribute, we retrieve only the data about the event
            $event = $this->Event->quickFetchEvent($data['ShadowAttribute']['event_id']);
            $event['Event']['ShadowAttribute'] = [$data['ShadowAttribute']];
        }

        $event = parent::normalizeData($event);
        return $event;
    }
}
