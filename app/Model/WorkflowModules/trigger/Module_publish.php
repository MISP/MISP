<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_publish extends WorkflowBaseModule
{
    public $id = 'publish';
    public $name = 'Publish';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'upload';
    public $inputs = 0;
    public $outputs = 1;

    public function __construct()
    {
        parent::__construct();
    }
}