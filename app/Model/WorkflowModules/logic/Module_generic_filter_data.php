<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_generic_filter_data extends WorkflowFilteringLogicModule
{
    public $id = 'generic-filter-data';
    public $name = 'Filter :: Generic';
    public $version = '0.2';
    public $description = 'Generic data filtering block. The module filters incoming data and forward the matching data to its output.';
    public $icon = 'filter';
    public $inputs = 1;
    public $outputs = 1;
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
                'id' => 'filtering-label',
                'label' => __('Filtering Label'),
                'type' => 'select',
                'options' => $this->_genFilteringLabels(),
                'default' => array_keys($this->_genFilteringLabels())[0],
            ],
            [
                'id' => 'selector',
                'label' => __('Data selector'),
                'type' => 'hashpath',
                'placeholder' => 'Event._AttributeFlattened.{n}',
                'hashpath' => [
                    'is_sub_selector' => false
                ]
            ],
            [
                'id' => 'value',
                'label' => __('Value'),
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
                'label' => __('Operator'),
                'type' => 'select',
                'default' => 'in',
                'options' => $this->operators,
            ],
            [
                'id' => 'hash_path',
                'label' => __('Hash path'),
                'type' => 'hashpath',
                'placeholder' => 'Tag.name',
                'hashpath' => [
                    'is_sub_selector' => true
                ]
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $selector = $params['selector']['value'];
        $path = $params['hash_path']['value'];
        $operator = $params['operator']['value'];
        $value = $params['value']['value'];
        $value_list = $params['value_list']['value'];
        $valueToEvaluate = $operator == 'in_or' ? $value_list : $value;
        $filteringLabel = $params['filtering-label']['value'];

        $newRData = $rData;
        if (empty($newRData['_unfilteredData'])) {
            $newRData['_unfilteredData'] = $rData;
        }
        $newRData['enabledFilters'][$filteringLabel] = [
            'selector' => $selector,
            'path' => $path,
            'operator' => $operator,
            'value' => $valueToEvaluate,
        ];

        $roamingData->setData($newRData);
        return true;
    }
}
