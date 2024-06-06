<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_stop_execution extends WorkflowBaseActionModule
{
    public $blocking = true;
    public $id = 'stop-execution';
    public $name = 'Stop execution';
    public $version = '0.2';
    public $description = 'Essentially stops the execution for blocking workflows. Do nothing for non-blocking ones';
    public $icon = 'ban';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];

    public function __construct()
    {
        parent::__construct();

        $this->params = [
            [
                'id' => 'message',
                'label' => 'Stop message',
                'type' => 'input',
                'default' => __('Execution stopped'),
                'placeholder' => __('Execution stopped'),
                'jinja_supported' => true,
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $errors[] = empty($params['message']['value']) ? $params['message']['default'] : $params['message']['value'];
        return false;
    }
}
