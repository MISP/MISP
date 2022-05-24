<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_feed_pull extends WorkflowBaseModule
{
    public $id = 'feed-pull';
    public $name = 'Feed pull';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'arrow-alt-circle-down';
    public $inputs = 0;
    public $outputs = 2;

    public function __construct()
    {
        parent::__construct();
    }
}
