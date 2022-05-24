<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_enrich_attribute extends WorkflowBaseModule
{
    public $id = 'enrich-attribute';
    public $name = 'Enrich Attribute';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'tag';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];


    public function __construct()
    {
        parent::__construct();
    }
}
