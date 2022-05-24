<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_mattermost_message extends WorkflowBaseModule
{
    public $id = 'mattermost-message';
    public $name = 'MatterMost Message';
    public $description = 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.';
    public $icon = 'comment-dots';
    public $inputs = 1;
    public $outputs = 0;
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
            [
                'id' => 'channel_name_select',
                'type' => 'select',
                'label' => 'Channel name',
                'default' => 'team-4_3_misp',
                'options' => [
                    'team-4_3_misp' => __('Team 4.3 MISP'),
                    'team-4_0_elite_as_one' => __('Team 4.0 Elite as One'),
                ],
            ],
            [
                'id' => 'channel_name_radio',
                'type' => 'radio',
                'label' => 'Channel name',
                'default' => 'team-4_3_misp',
                'options' => [
                    'team-4_3_misp' => __('Team 4.3 MISP'),
                    'team-4_0_elite_as_one' => __('Team 4.0 Elite as One'),
                ],
            ],
            [
                'type' => 'checkbox',
                'label' => __('Priority'),
                'default' => true,
            ],
        ];
    }
}
