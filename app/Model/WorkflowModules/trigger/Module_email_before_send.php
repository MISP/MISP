<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_email_before_send extends WorkflowBaseTriggerModule
{
    public $id = 'email-before-send';
    public $name = 'Email Before Send';
    public $description = '-WorkInProgress- This trigger is called just before a email is sent to a user.';
    public $icon = 'envelope';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;

    public function __construct()
    {
        parent::__construct();
    }
}
