<?php
// debug($data);
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'Workflow.id',
            'data_path' => 'Workflow.id',
        ],
        [
            'name' => __('Name'),
            'sort' => 'Workflow.name',
            'data_path' => 'Workflow.name',
        ],
        [
            'name' => __('Description'),
            'sort' => 'Workflow.description',
            'data_path' => 'Workflow.description',
        ],
        [
            'name' => __('Trigger Data Input Scope'),
            'data_path' => 'trigger_scope',
        ],
        [
            'name' => __('Trigger RestSearch Filters'),
            'data_path' => 'trigger_filters',
            'element' => 'json',
        ],
        [
            'name' => __('Run counter'),
            'sort' => 'Workflow.counter',
            'data_path' => 'Workflow.counter',
        ],
        [
            'name' => __('Last Update'),
            'class' => 'short',
            'sort' => 'Workflow.timestamp',
            'data_path' => 'Workflow.timestamp',
            'element' => 'datetime',
        ],
        [
            'name' => __('Debug enabled'),
            'sort' => 'Workflow.debug_enabled',
            'class' => 'short',
            'data_path' => 'Workflow.debug_enabled',
            'element' => 'checkbox_action',
            'onclick' => "enableWorkflowDebugMode(%s, %s)",
            'onclick_params_data_path' => ['Workflow.id', 'Workflow.debug_enabled'],
            'title' => __('Set the workflow in debug mode. Each nodes will send data to the provided debug URL')
        ],
        [
            'name' => __('Enabled'),
            'sort' => 'disabled',
            'class' => 'short',
            'data_path' => 'disabled',
            'element' => 'booleanOrNA',
            'boolean_reverse' => true,
            'colors' => true,
            'title' => __('Only enabled workflows will be executed when their trigger is called')
        ],
    ];

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'children' => [
                        [
                            'children' => [
                                [
                                    'text' => __('Add Ad-Hoc Workflows'),
                                    'fa-icon' => 'plus',
                                    'url' => $baseurl . '/workflows/add',
                                    'requirement' => $isSiteAdmin,
                                ]
                            ]
                        ],
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'cancel' => array(
                                'fa-icon' => 'times',
                                'title' => __('Remove filters'),
                                'onClick' => 'cancelSearch',
                            )
                        ]
                    ],
                ],
                'fields' => $fields,
                'title' => __('Ad-Hoc Workflows'),
                'description' => __('You can create ad-hoc workflows that needs to be launch manually'),
                'actions' => [
                    [
                        'title' => __('Run Workflow'),
                        'icon' => 'play-circle',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/executeWorkflow',
                        'url_params_data_paths' => ['Workflow.id'],
                        'postLinkConfirm' => __('Are you sure you want to run this workflow?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && $options['datapath']['trigger_scope'] == 'events';
                            },
                            'options' => array(
                                'datapath' => array(
                                    'trigger_scope' => 'trigger_scope'
                                )
                            )
                        ),
                    ],
                    [
                        'title' => __('Enable'),
                        'icon' => 'play',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/toggleModule',
                        'url_params_data_paths' => ['id'],
                        'url_suffix' => '/1/1',
                        'postLinkConfirm' => __('Are you sure you want to enable this workflow?'),
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
                        'postLinkConfirm' => __('Are you sure you want to disable this workflow?'),
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
                        'url' => $baseurl . '/workflows/view',
                        'url_params_data_paths' => ['Workflow.id'],
                        'icon' => 'eye',
                    ],
                    [
                        'url' => $baseurl . '/workflows/editor',
                        'url_params_data_paths' => ['Workflow.id'],
                        'icon' => 'code',
                        'dbclickAction' => true,
                    ],
                    [
                        'url' => $baseurl . '/workflows/edit',
                        'url_params_data_paths' => ['Workflow.id'],
                        'icon' => 'edit',
                    ],
                    [
                        'onclick' => sprintf(
                        'openGenericModal(\'%s/workflows/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'Workflow.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);
