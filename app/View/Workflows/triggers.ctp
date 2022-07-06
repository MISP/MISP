<?php
    $fields = [
        [
            'name' => __('Module name'),
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
            'name' => __('Blocking Workflow'),
            'sort' => 'blocking',
            'data_path' => 'blocking',
            'element' => 'boolean',
            'colors' => true,
        ],
        [
            'name' => __('Enabled'),
            'sort' => 'disabled',
            'class' => 'short',
            'data_path' => 'disabled',
            'element' => 'booleanOrNA',
            'boolean_reverse' => true,
            'colors' => true,
        ],
    ];

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'stupid_pagination' => true,
                'data' => $data,
                'top_bar' => [
                ],
                'fields' => $fields,
                'icon' => 'flag',
                'title' => __('Triggers'),
                'description' => __('List the available triggers that can be listened to by workflows'),
                'actions' => [
                    [
                        'title' => __('Enable'),
                        'icon' => 'play',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/toggleModule',
                        'url_params_data_paths' => ['id'],
                        'url_suffix' => '/1/1',
                        'postLinkConfirm' => __('Are you sure you want to enable this trigger?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && $options['datapath']['disabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'disabled' => 'disabled'
                                )
                            )
                        ),
                    ],
                    [
                        'title' => __('Disable'),
                        'icon' => 'stop',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/toggleModule',
                        'url_params_data_paths' => ['id'],
                        'url_suffix' => '/0/1',
                        'postLinkConfirm' => __('Are you sure you want to disable this trigger?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && !$options['datapath']['disabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'disabled' => 'disabled'
                                )
                            )
                        ),
                    ],
                    [
                        'title' => __('Edit associated workflows'),
                        'url' => $baseurl . '/workflows/editor',
                        'url_params_data_paths' => ['id'],
                        'icon' => 'code',
                        'dbclickAction' => true,
                    ],
                    [
                        'title' => __('View execution logs'),
                        'url' => $baseurl . '/admin/logs/index/model:Workflow/action:execute_workflow',
                        'url_named_params_data_paths' => ['model_id' => 'Workflow.id'],
                        'icon' => 'list-alt',
                        'complex_requirement' => [
                            'function' => function ($row, $options) {
                                return !empty($row['Workflow']);
                            },
                        ],
                    ],
                    [
                        'title' => __('View trigger details'),
                        'url' => $baseurl . '/workflows/moduleView',
                        'url_params_data_paths' => ['id'],
                        'icon' => 'eye',
                    ],
                ]
            ]
        ]
    ]);
