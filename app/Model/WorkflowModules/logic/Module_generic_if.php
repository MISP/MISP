<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_generic_if extends WorkflowBaseLogicModule
{
    public $id = 'generic-if';
    public $name = 'IF :: Generic';
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
                'type' => 'input',
                'placeholder' => 'Attribute.{n}.Tag',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);
        $path = $params['hash_path']['value'];
        $operator = $params['operator']['value'];
        $value = $params['value']['value'];
        $data = $roamingData->getData();
        $extracted = [];
        if ($operator == 'equals' || $operator == 'not_equals') {
            $extracted = Hash::get($data, $path, []);
        } else {
            $extracted = Hash::extract($data, $path);
        }
        $eval = $this->evaluateCondition($extracted, $operator, $value);
        return !empty($eval);
    }
}
