<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_filter_timestamp extends WorkflowFilteringLogicModule
{
    public $id = 'filter-timestamp';
    public $isFiltering = true;
    public $name = 'Filter :: Timestamp';
    public $version = '0.1';
    public $description = 'Timestamp filtering block. The module filters incoming data and forward the matching data to its output.';
    public $icon = 'filter';
    public $inputs = 1;
    public $outputs = 1;
    public $params = [];

    private $Attribute;
    private $operators = [
        'greater' => 'Within',
        'less' => 'Not within',
        'since' => 'Since (timestamp)',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $this->params = [
            [
                'id' => 'filtering-label',
                'label' => __('Filtering Label'),
                'type' => 'select',
                'options' => $this->_genFilteringLabels(),
                'default' => array_keys($this->_genFilteringLabels())[0],
            ],
            [
                'id' => 'target',
                'label' => __('Target'),
                'type' => 'select',
                'default' => 'attribute',
                'options' => [
                    'object' => __('Object'),
                    'attribute' => __('Attribute'),
                    'event_report' => __('Event Report'),
                ],
            ],
            [
                'id' => 'operator',
                'label' => __('Operator'),
                'type' => 'select',
                'default' => 'greater',
                'options' => $this->operators,
            ],
            [
                'id' => 'value',
                'label' => __('Value'),
                'type' => 'input',
                'placeholder' => '3d',
                'default' => '30d'
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);

        $target = $params['target']['value'];
        $operator = $params['operator']['value'];
        $value = $params['value']['value'];

        $filteringLabel = $params['filtering-label']['value'];

        if ($operator == 'since') {
            if (!is_numeric($value)) {
                return false;
            }
            $operator = 'greater';
        }

        $newRData = $rData;
        if (empty($newRData['_unfilteredData'])) {
            $newRData['_unfilteredData'] = $rData;
        }

        $path = 'timestamp';
        if ($target == 'object') {
            $selector = 'Event.Object';
        } else if ($target == 'attribute') {
            $selector = 'Event._AttributeFlattened';
        } else if ($target == 'event_report') {
            $selector = 'Event.EventReport';
        }

        $resolvedTimestamp = $this->Attribute->setTimestampConditions($value, [], '', true);

        $newRData['enabledFilters'][$filteringLabel] = [
            'selector' => $selector,
            'path' => $path,
            'operator' => $operator,
            'value' => $resolvedTimestamp,
        ];

        if ($target == 'attribute') {
            // Also filter attributes in the Attribute key
            $selector = 'Event.Attribute';
            $newRData['enabledFilters'][$filteringLabel . '_2'] = [
                'selector' => $selector,
                'path' => $path,
                'operator' => $operator,
                'value' => $resolvedTimestamp,
            ];
        }

        $roamingData->setData($newRData);
        return true;
    }
}
