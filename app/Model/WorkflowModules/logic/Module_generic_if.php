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
                'type' => 'input',
                'label' => 'Value',
                'placeholder' => 'tlp:red',
            ],
            [
                'type' => 'select',
                'label' => 'Operator',
                'default' => 'in',
                'options' => $this->operators,
            ],
            [
                'type' => 'input',
                'label' => 'Hash path',
                'placeholder' => 'Attribute.{n}.Tag',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);
        $path = $params['Hash path']['value'];
        $operator = $params['Operator']['value'];
        $value = $params['Value']['value'];
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
