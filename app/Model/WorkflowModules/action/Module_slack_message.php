<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_slack_message extends WorkflowBaseModule
{
    public $id = 'slack-message';
    public $name = 'Slack Message';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'tag';
    public $icon_class = 'fab';
    public $inputs = 1;
    public $outputs = 0;
    public $params = [];


    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'type' => 'select',
                'label' => 'Channel name',
                'default' => 'team-4_3_misp',
                'options' => [
                    'team-4_3_misp' => __('Team 4.3 MISP'),
                    'team-4_0_elite_as_one' => __('Team 4.0 Elite as One'),
                ],
            ],
        ];
    }
}
