<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_filter_tag extends WorkflowFilteringLogicModule
{
    public $id = 'filter-tag';
    public $isFiltering = true;
    public $name = 'Filter :: Tag';
    public $version = '0.3';
    public $description = 'Tag filtering block. The module filters incoming data and forward the matching data to its output.';
    public $icon = 'filter';
    public $inputs = 1;
    public $outputs = 1;
    public $params = [];

    private $Tag;
    private $operators = [
        'in_or' => 'Is tagged with any (OR)',
        'in_and' => 'Is tagged with all (AND)',
        'not_in_or' => 'Is not tagged with any (OR)',
        'not_in_and' => 'Is not tagged with all (AND)',
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
                'id' => 'scope',
                'label' => 'Scope',
                'type' => 'select',
                'options' => [
                    'attribute' => __('Attributes'),
                    'event_attribute' => __('Inherited Attributes'),
                    'event_report' => __('Event Report'),
                    'inherited_report' => __('Inherited Event Report'),
                ],
                'default' => 'event_attribute',
            ],
            [
                'id' => 'condition',
                'label' => 'Condition',
                'type' => 'select',
                'default' => 'in_or',
                'options' => $this->operators,
            ],
            [
                'id' => 'tags',
                'label' => __('Tags'),
                'type' => 'picker',
                'multiple' => true,
                'picker_options' => [
                    'select_options_url' => '/tags/fastIndex/0.json',
                ],
                'placeholder' => __('Pick a tag'),
            ],
            [
                'id' => 'clusters',
                'label' => __('Galaxy Clusters'),
                'type' => 'picker',
                'multiple' => true,
                'picker_options' => [
                    'select_options_url' => '/tags/fastIndex/1.json',
                ],
                'placeholder' => __('Pick a Galaxy Cluster'),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);

        $selectedTags = !empty($params['tags']['value']) ? $params['tags']['value'] : [];
        $selectedClusters = !empty($params['clusters']['value']) ? $params['clusters']['value'] : [];
        $selectedClusters = array_map(function ($tagName) {
            return "misp-galaxy:{$tagName}"; // restored stripped part for display purposes
        }, $selectedClusters);
        $allSelectedTags = array_merge($selectedTags, $selectedClusters);
        $operator = $params['condition']['value'];
        $scope = $params['scope']['value'];

        if ($scope == 'event') {
            // Due to a bug introduce in this module v0.2, event was the unsupported default value
            $scope == 'event_attribute';
        }

        $filteringLabel = $params['filtering-label']['value'];

        $newRData = $rData;
        if (empty($newRData['_unfilteredData'])) {
            $newRData['_unfilteredData'] = $rData;
        }

        if ($scope == 'attribute' || $scope == 'event_attribute') {
            $selector = 'Event._AttributeFlattened';
            $path = $scope == 'event_attribute' ? '_allTags.{n}.name' : 'Tag.{n}.name';
            $value = $allSelectedTags;
            $newRData['enabledFilters'][$filteringLabel] = [
                'selector' => $selector,
                'path' => $path,
                'operator' => $operator,
                'value' => $value,
            ];

            // Also filter attributes in the Attribute key
            $selector = 'Event.Attribute';
            $newRData['enabledFilters'][$filteringLabel . '_2'] = [
                'selector' => $selector,
                'path' => $path,
                'operator' => $operator,
                'value' => $value,
            ];
        } else if ($scope == 'event_report' || $scope == 'inherited_report') {
            $selector = 'Event.EventReport';
            $path = $scope == 'inherited_report' ? '_allTags.{n}.name' : 'Tag.{n}.name';
            $value = $allSelectedTags;
            $newRData['enabledFilters'][$filteringLabel] = [
                'selector' => $selector,
                'path' => $path,
                'operator' => $operator,
                'value' => $value,
            ];
        }

        $roamingData->setData($newRData);
        return true;
    }
}
