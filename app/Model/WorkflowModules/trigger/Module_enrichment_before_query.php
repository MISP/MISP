<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_enrichment_before_query extends WorkflowBaseTriggerModule
{
    public $id = 'enrichment-before-query';
    public $name = 'Enrichment Before Query';
    public $description = 'This trigger is called just before a query against the enrichment service is done';
    public $icon = 'asterisk';
    public $inputs = 0;
    public $outputs = 1;
    public $blocking = true;

    public function __construct()
    {
        parent::__construct();
    }
}
