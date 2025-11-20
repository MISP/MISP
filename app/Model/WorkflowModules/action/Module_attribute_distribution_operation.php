<?php
include_once APP . 'Model/WorkflowModules/action/Module_attribute_edition_operation.php';

class Module_attribute_distribution_operation extends Module_attribute_edition_operation
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'attribute_distribution_operation';
    public $name = 'Attribute distribution operation';
    public $description = 'Set the Attribute\'s distribution to the selected level';
    public $icon = 'edit';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    private $MispAttribute;
    private $SharingGroup;

    public function __construct()
    {
        parent::__construct();
        $this->MispAttribute = ClassRegistry::init('MispAttribute');
        $distributionLevels = $this->MispAttribute->shortDist;
        $distribution_param = [];
        foreach ($distributionLevels as $i => $text) {
            $distribution_param[] = ['name' => $text, 'value' => $i];
        }

        $this->SharingGroup = ClassRegistry::init('SharingGroup');
        $sharing_groups = Hash::combine($this->SharingGroup->fetchAllSharingGroup(), '{n}.SharingGroup.id', '{n}.SharingGroup.name');

        $this->params = [
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
        if ($matchingItems === false) {
            return true;
        }
        $result = $this->__saveAttributes($matchingItems, $rData, $params, $user);
        $success = $result['success'];
        $updatedRData = $result['updated_rData'];
        $roamingData->setData($updatedRData);
        return $success;
    }

    protected function _editAttribute(array $attribute, array $rData, array $params): array
    {
        $attribute['distribution'] = $params['distribution']['value'];
        if ($attribute['distribution'] == 4) {
            $attribute['sharing_group_id'] = $params['sharing_group_id']['value'];
        }
        return $attribute;
    }
}
