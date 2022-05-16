<?php
    $fields = [
        [
            'name' => __('Trigger name'),
            'sort' => 'name',
            'data_path' => 'name',
            'element' => 'custom',
            'class' => 'bold',
            'function' => function ($row) {
                return sprintf('<i class="fa-fw %s"></i> %s', $this->FontAwesome->getClass($row['icon']), h($row['name']));
            }
        ],
        [
            'name' => __('Description'),
            'data_path' => 'description',
        ],
        [
            'name' => __('Workflow Execution Order'),
            'data_path' => 'execution_order',
            'element' => 'custom',
            'function' => function ($row) {
                return $this->element('Workflows/executionOrder', ['trigger' => $row]);
            }
        ],
        [
            'name' => __('Trigger Enabled'),
            'element' => 'boolean',
            'sort' => 'enabled',
            'class' => 'short',
            'data_path' => 'enabled',
        ],
    ];

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'stupid_pagination' => true,
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => __('Workflows Trigger'),
                'description' => __('List the available triggers as well as the workflows relying on them'),
                'actions' => [
                    [
                        'title' => __('Enable'),
                        'icon' => 'play',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/enableTrigger',
                        'url_params_data_paths' => ['id'],
                        'postLinkConfirm' => __('Are you sure you want to enable this trigger?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && !$options['datapath']['enabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'enabled' => 'enabled'
                                )
                            )
                        ),
                    ],
                    [
                        'title' => __('Disable'),
                        'icon' => 'stop',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/disableTrigger',
                        'url_params_data_paths' => ['id'],
                        'postLinkConfirm' => __('Are you sure you want to disable this trigger?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && $options['datapath']['enabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'enabled' => 'enabled'
                                )
                            )
                        ),
                    ],
                    [
                        'url' => $baseurl . '/workflows/trigger_view',
                        'url_params_data_paths' => ['Workflow.id'],
                        'icon' => 'eye'
                    ],
                ]
            ]
        ]
    ]);
