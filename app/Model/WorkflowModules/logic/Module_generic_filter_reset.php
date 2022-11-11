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
    // public $html_template = 'filter-remove';
    public $params = [];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'filtering-label',
                'label' => __('Filtering Label to remove'),
                'type' => 'select',
                'options' => ['all' => __('All filters')] + $this->_genFilteringLabels(),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors=[]): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $newRData = $rData['_unfilteredData'];
        $roamingData->setData($newRData);
        return true;
    }
}
