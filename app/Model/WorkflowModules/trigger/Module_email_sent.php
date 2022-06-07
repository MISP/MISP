<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_email_sent extends WorkflowBaseModule
{
    public $id = 'email-sent';
    public $name = 'Email sent';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'envelope';
    public $inputs = 0;
    public $outputs = 1;

    public function __construct()
    {
        parent::__construct();
    }
}
