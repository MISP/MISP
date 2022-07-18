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
    public $params = [];

    private $Attribute;
    private $operators = [
        'equals' => 'Is',
        'not_equals' => 'Is not',
        'more_restrictive_or_equal_than' => 'More restrictive or equal than',
        'more_permisive_or_equal_than' => 'More permisive or equal than',
    ];

    private const CONTEXT_EVENT = 'event';
    private const CONTEXT_ATTRIBUTE = 'attribute';
    private const CONTEXT_UNKOWN = 'unkown';

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
                'label' => 'Scope',
                'type' => 'select',
                'options' => [
                    'attribute' => __('Final Distribution of Attribute'),
                ],
                'default' => 'attribute',
            ],
            [
                'label' => 'Condition',
                'type' => 'select',
                'default' => 'equals',
                'options' => $this->operators,
            ],
            [
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

        $scope = $params['Scope']['value'];
        $operator = $params['Condition']['value'];
        $value = $params['Distribution']['value'];
        $data = $roamingData->getData();
        $finalDistribution = $this->__getPropagatedDistribution(
            $this->__extractData('event', $data),
            $this->__extractData('object', $data),
            $this->__extractData('attribute', $data)
        );
        if ($finalDistribution == -1) {
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
        $eval = $this->evaluateCondition($distribution_range, $operator, $finalDistribution);
        return !empty($eval);
    }

    /**
     * __getPath
     *
     * @param string $scope
     * @param array $data Data in the MISP core format. Can be coming from multiple context such as Event, Attribute, ..
     * @return false|string
     */
    private function __getPath($scope, array $data)
    {
        $path = false;
        $context = $this->__deduceContextFromData($data);
        if ($scope == 'attribute') {
            if ($context == self::CONTEXT_ATTRIBUTE) {
                $path = 'Attribute';
            } elseif ($context == self::CONTEXT_EVENT) {
                $path = 'Event.Attribute.0';
            }
        } else if ($scope == 'object') {
            if ($context == self::CONTEXT_ATTRIBUTE) {
                $path = 'Attribute.Object';
            } elseif ($context == self::CONTEXT_EVENT) {
                $path = 'Event.Attribute.0.Object';
            }
        } else {
            $scope = 'event';
            if ($context == self::CONTEXT_ATTRIBUTE) {
                $path = 'Attribute.Event';
            } elseif ($context == self::CONTEXT_EVENT) {
                $path = 'Event';
            }
        }
        return $path;
    }

    private function __extractData($scope, array $data): array
    {
        $path = $this->__getPath($scope, $data);
        $extracted = Hash::get($data, $path);
        return is_null($extracted) ? [] : $extracted;
    }

    /**
     * __deduceContextFromData
     *
     * @param array $data
     * @return string
     */
    private function __deduceContextFromData(array $data)
    {
        if (!empty($data['Event'])) {
            return self::CONTEXT_EVENT;
        } elseif (!empty($data['Attribute'])) {
            return self::CONTEXT_ATTRIBUTE;
        } else {
            self::CONTEXT_UNKOWN;
        }
    }

    /**
     * __getPropagatedDistribution Get the final distribution of the attribute where distribution of its parent (events/objects) is applied
     *
     * @param array $event
     * @param array $object
     * @param array $attribute
     * @return integer
     */
    private function __getPropagatedDistribution(array $event, array $object, array $attribute): int
    {
        $finalDistribution = intval($attribute['distribution']);
        if (!empty($object)) {
            $finalDistribution = min($finalDistribution, intval($object['distribution']));
        }
        $finalDistribution = min($finalDistribution, intval($event['distribution']));
        if ($attribute['distribution'] == 5) {
            $attribute['distribution'] = $event['distribution'];
        }
        if ($finalDistribution == 4) {
            $finalDistribution = -1; // ignore sharing group for now
        }
        return $finalDistribution;
    }
}
