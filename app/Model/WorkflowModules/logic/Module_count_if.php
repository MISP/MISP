<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_count_if extends WorkflowBaseLogicModule
{
    public $id = 'count-if';
    public $name = 'IF :: Count';
    public $description = 'Count IF / ELSE condition block. It counts the amount of entry selected by the provided hashpath. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $expect_misp_core_format = false;
    public $params = [];

    private $operators = [
        'equals' => 'Equals to',
        'not_equals' => 'Not Equals to',
        'greater' => 'Greater than',
        'greater_equals' => 'Greater or equals than',
        'less' => 'Less than',
        'less_equals' => 'Less or equals than',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'selector',
                'label' => __('Data selector to count'),
                'type' => 'hashpath',
                'placeholder' => 'Event.Tag.{n}.name',
                'hashpath' => [
                    'is_sub_selector' => false
                ]
            ],
            [
                'id' => 'operator',
                'label' => 'Condition',
                'type' => 'select',
                'default' => 'equals',
                'options' => $this->operators,
            ],
            [
                'id' => 'value',
                'label' => __('Value'),
                'type' => 'input',
                'placeholder' => '50',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $selector = $params['selector']['value'];
        $operator = $params['operator']['value'];
        $value = $params['value']['value'];

        $extracted = Hash::extract($rData, $selector);
        $amount = count($extracted ?? []);

        $eval = $this->evaluateCount($amount, $operator, $value);
        return $eval;
    }

    private function evaluateCount($amount, $operator, $value): bool
    {
        if ($operator == 'equals') {
            return $amount == $value;
        } elseif ($operator == 'not_equals') {
            return $amount != $value;
        } elseif ($operator == 'greater') {
            return $amount > $value;
        } elseif ($operator == 'greater_equals') {
            return $amount >= $value;
        } elseif ($operator == 'less') {
            return $amount < $value;
        } elseif ($operator == 'less_equals') {
            return $amount <= $value;
        }
        return false;
    }
}
