<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_distribution_if extends WorkflowBaseLogicModule
{
    public $id = 'distribution-if';
    public $name = 'IF :: Distribution';
    public $version = '0.3';
    public $description = 'Distribution IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $expect_misp_core_format = true;
    public $params = [];

    private $Attribute, $SharingGroup;
    private $operators = [
        'equals' => 'Is',
        'not_equals' => 'Is not',
        'more_restrictive_or_equal_than' => 'More restrictive or equal than',
        'more_permisive_or_equal_than' => 'More permisive or equal than',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->Attribute = ClassRegistry::init('Attribute');
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
                'id' => 'scope',
                'label' => 'Scope',
                'type' => 'select',
                'options' => [
                    'attribute' => __('Final distribution of the Attribute'),
                    'event' => __('Distribution of the Event'),
                ],
                'default' => 'attribute',
            ],
            [
                'id' => 'condition',
                'label' => 'Condition',
                'type' => 'select',
                'default' => 'equals',
                'options' => $this->operators,
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
                'multiple' => true,
                'options' => $sharing_groups,
                'default' => [],
                'placeholder' => __('Pick a sharing group'),
                'display_on' => [
                    'distribution' => '4',
                ],
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $data = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $data);

        $scope = $params['scope']['value'];
        $operator = $params['condition']['value'];
        $selected_distribution = $params['distribution']['value'];
        $selected_sharing_groups = !empty($params['sharing_group_id']['value']) ? $params['sharing_group_id']['value'] : [];
        $final_distribution = $this->__getPropagatedDistribution($data['Event']);
        if ($scope == 'attribute') {
            $final_distribution = $this->__getPropagatedDistribution(
                $data['Event'],
                $data['Event']['Attribute'][0]['Object'] ?? [],
                $data['Event']['Attribute'][0]
            );
        }
        if (!in_array($final_distribution, range(0, 4))) {
            $errors[] = __('Distribution level not supported');
            return false; // distribution  not supported
        }
        if ($selected_distribution == 4) {
            $final_sharing_group = $this->__extractSharingGroupIDs(
                $data['Event'],
                $data['Event']['Attribute'][0]['Object'] ?? [],
                $data['Event']['Attribute'][0],
                $scope
            );
            if ($operator == 'equals') {
                return empty($selected_sharing_groups) ? !empty($final_sharing_group) :
                    !array_diff($final_sharing_group, $selected_sharing_groups); // All sharing groups are in the selection
            } else if ($operator == 'not_equals') {
                return empty($selected_sharing_groups) ? empty($final_sharing_group) :
                    count(array_diff($final_sharing_group, $selected_sharing_groups)) == count($final_sharing_group); // All sharing groups are in the selection
            }
            $errors[] = __('Condition operator not supported for that distribution level');
            return false;
        } else {
            if ($operator == 'more_restrictive_or_equal_than') {
                $operator = 'in';
                $distribution_range = range(0, $selected_distribution);
            } else if ($operator == 'more_permisive_or_equal_than') {
                $operator = 'in';
                $distribution_range = range($selected_distribution, 3);
            } else {
                $distribution_range = intval($selected_distribution);
            }
        }
        $eval = $this->evaluateCondition($distribution_range, $operator, $final_distribution);
        return !empty($eval);
    }

    /**
     * __getPropagatedDistribution Get the final distribution of the attribute where distribution of its parent (events/objects) is applied
     *
     * @param array $event
     * @param array $object
     * @param array $attribute
     * @return integer
     */
    private function __getPropagatedDistribution(array $event, array $object=[], array $attribute=[]): int
    {
        $finalDistribution = 5;
        if (!empty($attribute)) {
            $finalDistribution = intval($attribute['distribution']);
        }
        if (!empty($object)) { // downgrade based on the object distribution
            $finalDistribution = $this->__getMostRestrictiveDistribution($finalDistribution, intval($object['distribution'])); // downgrade based on the object distribution
        }
        $finalDistribution = $this->__getMostRestrictiveDistribution($finalDistribution, intval($event['distribution'])); // downgrade based on the event distribution
        return $finalDistribution;
    }

    private function __getMostRestrictiveDistribution(int $distri1, int $distri2): int
    {
        if ($distri1 == 0 || $distri2 == 0) {
            return 0;
        }
        if ($distri1 == 4 || $distri2 == 4) {
            return 4;
        }
        return min($distri1, $distri2);
    }

    private function __extractSharingGroupIDs(array $event, array $object=[], array $attribute=[], $scope='event'): array
    {
        $sgIDs = [];
        if ($scope == 'event') {
            if (!empty($event) && $event['distribution'] == 4) {
                $sgIDs[] = $event['sharing_group_id'];
            }
            return $sgIDs;
        }
        if (!empty($event) && $event['distribution'] == 4) {
            $sgIDs[] = $event['sharing_group_id'];
        }
        if (!empty($attribute) && $attribute['distribution'] == 4) {
            $sgIDs[] = $attribute['sharing_group_id'];
        }
        if (!empty($object) && $object['distribution'] == 4) { // downgrade based on the object distribution
            $sgIDs[] = $object['sharing_group_id'];
        }
        return $sgIDs;
    }
}
