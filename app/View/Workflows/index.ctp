<?php
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'Workflow.id',
            'data_path' => 'Workflow.id',
        ],
        [
            'name' => __('Owner Org'),
            'sort' => 'Organisation',
            'data_path' => 'Organisation',
            'element' => 'org',
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
            'name' => __('Run counter'),
            'sort' => 'Workflow.counter',
            'data_path' => 'Workflow.counter',
        ],
        [
            'name' => __('Listening Triggers'),
            'data_path' => 'Workflow.listening_triggers',
            'element' => 'custom',
            'function' => function ($row) use ($baseurl) {
                return implode('<br />', array_map(function($trigger) use ($baseurl) {
                        return sprintf('<a href="%s/workflows/triggerView/%s" %s><i class="fa-fw %s"></i> %s</a>',
                            $baseurl,
                            h($trigger['id']),
                            !empty($trigger['disabled']) ? sprintf('class="%s" style="%s" title="%s"', 'muted', 'text-decoration: line-through;', __('Trigger disabled')) : '',
                            $this->FontAwesome->getClass($trigger['icon']),
                            h($trigger['id'])
                        );
                    }, $row['Workflow']['listening_triggers'])
                );
            }
        ],
        [
            'name' => __('Enabled'),
            'element' => 'boolean',
            'sort' => 'enabled',
            'class' => 'short',
            'data_path' => 'Workflow.enabled',
        ],
    ];


    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => [
                                'data' => [
                                    'type' => 'simple',
                                    'text' => __('Add Workflow'),
                                    'class' => 'btn btn-primary',
                                    'onClick' => 'openGenericModal',
                                    'onClickParams' => [
                                        sprintf(
                                            '%s/workflows/add',
                                            $baseurl
                                        )
                                    ]
                                ]
                            ]
                        ],
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
                'title' => __('Workflows'),
                'description' => __('You can create workflows relying on pipeline hooks to that can listen to triggers and then perform actions depending on some conditions'),
                'actions' => [
                    [
                        'title' => __('Enable'),
                        'icon' => 'play',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/enable',
                        'url_params_data_paths' => ['Workflow.id'],
                        'postLinkConfirm' => __('Are you sure you want to enable this workflow?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && !$options['datapath']['enabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'enabled' => 'Workflow.enabled'
                                )
                            )
                        ),
                    ],
                    [
                        'title' => __('Disable'),
                        'icon' => 'stop',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/disable',
                        'url_params_data_paths' => ['Workflow.id'],
                        'postLinkConfirm' => __('Are you sure you want to disable this workflow?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && $options['datapath']['enabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'enabled' => 'Workflow.enabled'
                                )
                            )
                        ),
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
                        'url' => $baseurl . '/workflows/export',
                        'url_params_data_paths' => ['Workflow.id'],
                        'title' => __('Export Workflow'),
                        'icon' => 'file-upload',
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
