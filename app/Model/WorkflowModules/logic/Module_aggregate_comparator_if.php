<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_aggregate_comparator_if extends WorkflowFilteringLogicModule
{
    public $id = 'aggregate_comparator_if';
    public $name = 'IF :: Aggregate Comparator';
    public $version = '0.4';
    public $description = 'Computes an aggregate over a field, then evaluates rhe result.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'if';
    public $params = [];

    private $operators = [
        'equals' => 'Equals',
        'not_equals' => 'Not equals',
        'greater' => 'Greater than',
        'greater_equals' => 'Greater or equal than',
        'less' => 'Less than',
        'less_equals' => 'Less or equal than',
        'in' => 'In',
        'not_in' => 'Not in',
    ];

    private $aggregation_type = [
        'count' => [
            'label' => 'Count',
            'fun' => 'aggregateCount',
        ],
        'sum' => [
            'label' => 'Sum',
            'fun' => 'aggregateSum',
        ],
        'avg' => [
            'label' => 'Average',
            'fun' => 'aggregateAvg',
        ],
        'min' => [
            'label' => 'Minimum',
            'fun' => 'aggregateMin',
        ],
        'max' => [
            'label' => 'Maximum',
            'fun' => 'aggregateMax',
        ],
        'unique_count' => [
            'label' => 'Unique count',
            'fun' => 'aggregateUniqueCount',
        ],
        'median' => [
            'label' => 'Median',
            'fun' => 'aggregateMedian',
        ],
    ];

    
    public function __construct()
    {
        parent::__construct();

        $aggregation_type_labels = [];
        foreach ($this->aggregation_type as $key => $data) {
            $aggregation_type_labels[$key] = $data['label'];
        }

        $this->params = [
            [
                'id' => 'aggregation_path',
                'label' => 'Aggregation Field Path',
                'type' => 'hashpath',
                'placeholder' => 'Attribute.{n}.Tag',
            ],
            [
                'id' => 'aggregation_type',
                'label' => 'Aggregation type',
                'type' => 'select',
                'default' => 'count',
                'options' => $aggregation_type_labels,
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
                'placeholder' => '42',
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);

        $aggregation_path = $params['aggregation_path']['value'];
        $aggregation_type = $params['aggregation_type']['value'];
        $operator = $params['operator']['value'];
        $value = $params['value']['value'];

        $extracted =  Hash::extract($rData, $aggregation_path);
        if (!is_array($extracted)) {
            $errors[] = 'Could not aggregate this field';
            return false;
        }
        $extracted = array_values(array_filter($extracted, fn($v) => $v !== null));
        $extracted = array_map('floatval', $extracted);

        $aggregated_value = $this->aggregate($aggregation_type, $extracted, $errors);

        $eval = $this->evaluateCondition($aggregated_value, $operator, $value);
        return !empty($eval);
    }

    public function aggregate($type, array $values, array &$errors = [])
    {
        if (!isset($this->aggregation_type[$type])) {
            $errors[] = "Unknown aggregation type: {$type}";
            return false;
        }

        return $this->{$this->aggregation_type[$type]['fun']}($values);
    }

    private function aggregateCount(array $values): int
    {
        return count($values);
    }

    private function aggregateSum(array $values): float
    {
        return array_sum($values);
    }

    private function aggregateAvg(array $values): float
    {
        return count($values) ? array_sum($values) / count($values) : 0;
    }

    private function aggregateMin(array $values)
    {
        return min($values);
    }

    private function aggregateMax(array $values)
    {
        return max($values);
    }

    private function aggregateUniqueCount(array $values): int
    {
        return count(array_unique($values, SORT_REGULAR));
    }

    private function aggregateMedian(array $values)
    {
        sort($values);
        $count = count($values);

        if ($count === 0) {
            return null;
        }

        $middle = intdiv($count, 2);

        return ($count % 2)
            ? $values[$middle]
            : ($values[$middle - 1] + $values[$middle]) / 2;
    }
}
