<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_generic_filter_reset extends WorkflowFilteringLogicModule
{
    public $id = 'generic-filter-reset';
    public $name = 'Filter :: Remove filter';
    public $description = 'Reset filtering';
    public $icon = 'redo-alt';
    public $inputs = 1;
    public $outputs = 1;
    public $params = [];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'filtering-label',
                'label' => __('Filtering Label to remove'),
                'type' => 'select',
                'default' => 'all',
                'options' => ['all' => __('All filters')] + $this->_genFilteringLabels(),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $filteringLabel = $params['filtering-label']['value'];

        $newRData = $rData['_unfilteredData'];
        if (in_array($filteringLabel, array_keys($this->_genFilteringLabels()))) {
            unset($newRData['enabledFilters'][$filteringLabel]);
        } else if ($filteringLabel === 'all') {
            $newRData['enabledFilters'] = [];
        }
        $roamingData->setData($newRData);
        return true;
    }
}
