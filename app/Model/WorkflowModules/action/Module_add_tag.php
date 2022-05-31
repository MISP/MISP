<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_add_tag extends WorkflowBaseModule
{
    public $id = 'add-tag';
    public $name = 'Add tag';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'tag';
    public $inputs = 1;
    public $outputs = 1;
    public $params = [];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'input',
                'label' => 'Tag name',
                'default' => 'tlp:red',
                'placeholder' => __('Enter tag name')
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        return true;
        // $errors[] = __('Could not add tag!');
        // return false;
    }
}
