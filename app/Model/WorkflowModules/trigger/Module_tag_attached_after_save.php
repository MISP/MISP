<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_tag_attached_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'tag-attached-after-save';
    public $scope = 'tag';
    public $name = 'Tag Attached After Save';
    public $description = 'This trigger is called just after a Tag has been attached to an Event or an Attribute.';
    public $icon = 'tags';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = false;
    public $misp_core_format = true;
    public $trigger_overhead = self::OVERHEAD_HIGH;
    public $params = [];

    public function __construct()
    {
        parent::__construct();
        $this->trigger_overhead_message = __('This trigger is called each time a Tag has been attached. This means that when a large quantity of Tags are being saved (e.g. Feed pulling or synchronisation), the workflow will be run for as many time as there are Tag attached.');

        $this->params = [
            [
                'id' => 'scope',
                'label' => __('Scope'),
                'type' => 'select',
                'options' => [
                    'event' => __('Event'),
                    'attribute' => __('Attributes'),
                    'any' => __('Any'),
                ],
                'default' => 'event',
            ],
            [
                'id' => 'locality',
                'label' => __('Tag Locality'),
                'type' => 'select',
                'options' => [
                    'local' => __('Local'),
                    'global' => __('Global'),
                    'any' => __('Any'),
                ],
                'default' => 'local',
            ],
            [
                'id' => 'tag',
                'label' => __('Tags'),
                'type' => 'input',
                'placeholder' => __('Type a tag'),
            ]
        ];
    }

    public function normalizeData(array $data)
    {
        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('Attribute');

        if (empty($data['Tag'])) {
            return false;
        }
        $event = $this->Event->quickFetchEvent($data['Tag']['event_id']);

        // We are missing data such as tags or objects.
        if (!empty($data['Tag']['attribute_id'])) {
            $attribute = $this->Attribute->fetchAttribute($data['Tag']['attribute_id']);
    
            if (!empty($attribute['Object'])) {
                $event['Event']['Object'] = [$attribute['Object']];
                $event['Event']['Object'][0]['Attribute'] = [$attribute['Attribute']];
            } else {
                $event['Event']['Attribute'] = [$attribute['Attribute']];
            }
        }

        $event = parent::normalizeData($event);
        return $event;
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $scope = $params['scope']['value'];
        $locality = $params['locality']['value'];
        $tag = $params['tag']['value'];

        if ($scope == 'attribute' && empty($rData['Tag']['attribute_id'])) {
            return false;
        } else if ($scope == 'event' && !empty($rData['Tag']['attribute_id'])) {
            return false;
        }

        if ($locality == 'local' && empty($rData['Tag']['local'])) {
            return false;
        } else if ($locality == 'global' && !empty($rData['Tag']['local'])) {
            return false;
        }

        if (!empty($tag) && $rData['Tag']['name'] != $tag) {
            return false;
        }

        return true;
    }
}
