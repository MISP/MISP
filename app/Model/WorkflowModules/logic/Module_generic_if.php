<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_generic_if extends WorkflowBaseLogicModule
{
    public $id = 'generic-if';
    public $name = 'IF :: Generic';
    public $version = '0.2';
    public $description = 'Generic IF / ELSE condition block. The `then` output will be used if the encoded conditions is satisfied, otherwise the `else` output will be used.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $params = [];

    private $operators = [
        'in' => 'In',
        'not_in' => 'Not in',
        'equals' => 'Equals',
        'not_equals' => 'Not equals',
        'any_value' => 'Any value',
        'in_or' => 'Any value from',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'value',
                'label' => 'Value',
                'type' => 'input',
                'placeholder' => 'tlp:red',
                'display_on' => [
                    'operator' => ['in', 'not_in', 'equals', 'not_equals',],
                ],
            ],
            [
                'id' => 'value_list',
                'label' => __('Value list'),
                'type' => 'picker',
                'picker_create_new' => true,
                'placeholder' => '[\'ip-src\', \'ip-dst\']',
                'display_on' => [
                    'operator' => 'in_or',
                ],
            ],
            [
                'id' => 'operator',
                'label' => 'Operator',
                'type' => 'select',
                'default' => 'in',
                'options' => $this->operators,
            ],
            [
                'id' => 'hash_path',
                'label' => 'Hash path',
                'type' => 'hashpath',
                'placeholder' => 'Attribute.{n}.Tag',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $data = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $data);
        $path = $params['hash_path']['value'];
        $operator = $params['operator']['value'];
        $value = $params['value']['value'];
        $value_list = $params['value_list']['value'];
        $valueToEvaluate = $operator == 'in_or' ? $value_list : $value;
        $extracted = [];
        if ($operator == 'equals' || $operator == 'not_equals') {
            $extracted = Hash::get($data, $path, []);
        } else {
            $extracted = Hash::extract($data, $path);
        }
        if ($operator == 'any_value' && !empty($extracted)) {
            return true;
        }
        $eval = $this->evaluateCondition($extracted, $operator, $valueToEvaluate);
        return !empty($eval);
    }
}
