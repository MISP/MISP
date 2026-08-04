<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_blueprint_logic_module extends WorkflowBaseLogicModule
{
    public $disabled = true;
    public $id = 'blueprint-logic-module';
    public $name = 'Blueprint logic module';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'shapes';
    public $inputs = 1;
    public $outputs = 2;
    public $params = [];

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $data = $roamingData->getData();
        // Returning true will make the execution flow take the first output of this module. Otherwise, the second output will be used.
        return true;
    }
}
