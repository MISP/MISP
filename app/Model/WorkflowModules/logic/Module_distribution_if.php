<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_distribution_if extends WorkflowBaseLogicModule
{
    public $id = 'distribution-if';
    public $name = 'IF :: Distribution';
    public $description = 'Distribution IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $expect_misp_core_format = true;
    public $params = [];

    private $Attribute;
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
        unset($distributionLevels[4]);
        unset($distributionLevels[5]);
        $distribution_param = [];
        foreach ($distributionLevels as $i => $text) {
            $distribution_param[] = ['name' => $text, 'value' => $i];
        }
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
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);

        $scope = $params['scope']['value'];
        $operator = $params['condition']['value'];
        $value = $params['distribution']['value'];
        $data = $roamingData->getData();
        $final_distribution = $this->__getPropagatedDistribution($data['Event']);
        if ($scope == 'attribute') {
            $final_distribution = $this->__getPropagatedDistribution(
                $data['Event'],
                $data['Event']['Attribute'][0]['Object'] ?? [],
                $data['Event']['Attribute'][0]
            );
        }
        if ($final_distribution == -1) {
            return false; // distribution  not supported
        }
        if ($operator == 'more_restrictive_or_equal_than') {
            $operator = 'in';
            $distribution_range = range(0, $value);
        } else if ($operator == 'more_permisive_or_equal_than') {
            $operator = 'in';
            $distribution_range = range($value, 3);
        } else {
            $distribution_range = intval($value);
        }
        if ($operator == 'more_restrictive_or_equal_than' || $operator == 'more_permisive_or_equal_than') {
            $distribution_range = array_diff($value, [4]); // ignore sharing_group for now
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
            $finalDistribution = min($finalDistribution, intval($object['distribution']));
        }
        $finalDistribution = min($finalDistribution, intval($event['distribution'])); // downgrade based on the event distribution
        if (!empty($attribute)) {
            if ($attribute['distribution'] == 5) { // mirror distribution for the one of the event
                $attribute['distribution'] = intval($event['distribution']);
            }
        }
        if ($finalDistribution == 4) {  // ignore sharing group for now
            $finalDistribution = -1;
        }
        return $finalDistribution;
    }
}
