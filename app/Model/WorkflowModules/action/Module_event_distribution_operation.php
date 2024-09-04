<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_event_distribution_operation extends WorkflowBaseModule
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'Module_event_distribution_operation';
    public $name = 'Event distribution operation';
    public $description = 'Set the Event\'s distribution to the selected level';
    public $icon = 'edit';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = false;
    public $expect_misp_core_format = true;
    public $params = [];

    private $Attribute, $SharingGroup, $Event;

    public function __construct()
    {
        parent::__construct();
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $this->Event = ClassRegistry::init('Event');
        $distributionLevels = $this->Attribute->shortDist;
        unset($distributionLevels[5]);
        $distribution_param = [];
        foreach ($distributionLevels as $i => $text) {
            $distribution_param[] = ['name' => $text, 'value' => $i];
        }

        $this->SharingGroup = ClassRegistry::init('SharingGroup');
        $sharing_groups = Hash::combine($this->SharingGroup->fetchAllSharingGroup(), '{n}.SharingGroup.id', '{n}.SharingGroup.name');

        $this->params = [
            [
                'id' => 'freeze',
                'label' => __('Preserve timestamp and published state'),
                'type' => 'select',
                'options' => [
                    'modify' => __('Modify timestamp and unpublish'),
                    'freeze' => __('Freeze timestamp and keep published state'),
                ],
                'default' => 'modify',
            ],
            [
                'id' => 'distribution',
                'label' => 'Distribution',
                'type' => 'select',
                'default' => '0',
                'options' => $distribution_param,
                'placeholder' => __('Pick a distribution'),
            ],
            [
                'id' => 'sharing_group_id',
                'label' => 'Sharing Groups',
                'type' => 'picker',
                'multiple' => false,
                'options' => $sharing_groups,
                'default' => [],
                'placeholder' => __('Pick a sharing group'),
                'display_on' => [
                    'distribution' => '4',
                ],
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $user = $roamingData->getUser();

        $matchingItems = $this->getMatchingItemsForAttributes($node, $rData);
        if ($matchingItems === false || count($matchingItems) == 0) {
            return true;
        }

        $result = $this->__saveEvent($rData, $rData, $params, $user);
        $success = $result['success'];
        $updatedRData = $result['updated_rData'];
        $roamingData->setData($updatedRData);
        return $success;
    }

    protected function _editEvent(array $event, array $rData, array $params): array
    {
        $event['Event']['distribution'] = $params['distribution']['value'];
        if ($event['Event']['distribution'] == 4) {
            $event['Event']['sharing_group_id'] = $params['sharing_group_id']['value'];
        }
        return $event;
        
    }

    protected function __saveEvent(array $event, array $rData, array $params, array $user): array
    {
        $freezeTimestamp = $params['freeze']['value'] == 'freeze';
        $newEvent = $this->_editEvent($event, $rData, $params);
        $saved = $this->Event->save($newEvent);
        $saveSuccess = !empty($saved);
        if ($saveSuccess) {
            if (!$freezeTimestamp) {
                $this->Event->touch($newEvent['Event']['id']);
            }
            $rData = $newEvent;
        }
        return [
            'success' => $saveSuccess,
            'updated_rData' => $rData,
        ];
    }
}
