<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_if extends WorkflowBaseModule
{
    public $id = 'if';
    public $name = 'IF';
    public $description = 'Simple IF / ELSE condition block. Use the `then` output for execution path satifying the conditions passed to the `IF` block.';
    public $icon = 'code-branch';
    public $inputs = 1;
    public $outputs = 2;
    public $html_template = 'IF';
    public $params = [];

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'textarea',
                'label' => 'Event Conditions',
                'default' => '',
                'placeholder' => '{ "tags" : { "AND" : [ "tlp : green" , "Malware" ] , "NOT" : [ "%ransomware%" ]}}'
            ],
        ];
    }
}
