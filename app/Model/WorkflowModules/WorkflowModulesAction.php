<?php
include_once 'WorkflowModules.php';

class WorkflowModulesAction extends WorkflowModules
{
    /** @var PubSubTool */
    private static $loadedPubSubTool;

    protected function loadModules(): array
    {
        return [
            [
                'id' => 'add-tag',
                'name' => 'Add Tag',
                'icon' => 'tag',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'input',
                        'label' => 'Tag name',
                        'default' => 'tlp:red',
                        'placeholder' => __('Enter tag name')
                    ],
                ],
                'outputs' => 0,
                // 'disabled' => true,
            ],
            [
                'id' => 'enrich-attribute',
                'name' => 'Enrich Attribute',
                'icon' => 'asterisk',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'outputs' => 0,
                'disabled' => true,
            ],
            [
                'id' => 'slack-message',
                'name' => 'Slack Message',
                'icon' => 'slack',
                'icon_class' => 'fab',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'select',
                        'label' => 'Channel name',
                        'default' => 'team-4_3_misp',
                        'options' => [
                            'team-4_3_misp' => __('Team 4.3 MISP'),
                            'team-4_0_elite_as_one' => __('Team 4.0 Elite as One'),
                        ],
                    ],
                ],
                'outputs' => 0,
            ],
            [
                'id' => 'mattermost-message',
                'name' => 'MatterMost Message',
                'icon' => 'comment-dots',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
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
                ],
                'outputs' => 0,
            ],
            [
                'id' => 'send-email',
                'name' => 'Send Email',
                'icon' => 'envelope',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'select',
                        'label' => 'Email template',
                        'default' => 'default',
                        'options' => [
                            'default',
                            'TLP marking',
                        ],
                    ],
                ],
                'outputs' => 0,
                'disabled' => true,
            ],
            [
                'name' => 'Do nothing',
                'id' => 'dev-null',
                'icon' => 'ban',
                'description' => 'Essentially a /dev/null',
                'module_type' => 'action',
                'outputs' => 0,
            ],
            [
                'name' => 'Push to ZMQ',
                'id' => 'push-zmq',
                'icon' => 'wifi',
                'icon_class' => 'fas fa-rotate-90',
                'description' => 'Push to the ZMQ channel',
                'module_type' => 'action',
                'params' => [
                    [
                        'type' => 'input',
                        'label' => 'ZMQ Topic',
                        'default' => 'from-misp-workflow',
                    ],
                    [
                        'type' => 'input',
                        'label' => 'Content',
                        'default' => '',
                        'placeholder' => 'Whatever text to be published'
                    ],
                ],
                'outputs' => 0,
                'disabled' => false,
                // '_handler' => $this->pushZmqHandler,
                '_handler' => 'pushZmqHandler',
            ],
        ];
    }

    public function pushZmqHandler($node, $data)
    {
        if (!self::$loadedPubSubTool) {
            App::uses('PubSubTool', 'Tools');
            $pubSubTool = new PubSubTool();
            $pubSubTool->initTool();
            self::$loadedPubSubTool = $pubSubTool;
        }
        $pubSubTool = self::$loadedPubSubTool;
        debug($node);
        $params = $this->getParams($node);
        $pubSubTool->workflow_push([
            'passed' => $params['Content']['value']
        ]);
    }
}
