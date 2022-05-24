<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_send_email extends WorkflowBaseModule
{
    public $id = 'send-email';
    public $name = 'Send Email';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'tag';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'select',
                'label' => 'Email template',
                'default' => 'default',
                'options' => [
                    'default',
                    'TLP marking',
                ],
            ],
        ];
    }
}
