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
            'name' => __('Module Type'),
            'sort' => 'module_type',
            'class' => 'short',
            'data_path' => 'module_type',
        ],
        [
            'name' => __('Is blocking'),
            'sort' => 'is_blocking',
            'class' => 'short',
            'data_path' => 'is_blocking',
            'element' => 'boolean',
        ],
        [
            'name' => __('Is misp-module'),
            'sort' => 'is_misp_module',
            'class' => 'short',
            'data_path' => 'is_misp_module',
            'element' => 'boolean',
            'requirement' => $indexType == 'action',
        ],
        [
            'name' => __('Module Enabled'),
            'sort' => 'disabled',
            'class' => 'short',
            'data_path' => 'disabled',
            'element' => 'booleanOrNA',
            'boolean_reverse' => true
        ],
    ];

    if (!empty($module_service_error)) {
        echo sprintf('<div class="alert alert-error"><strong>%s</strong> %s</div>', __('MISP Modules Action Services is not reachable!'), __('Some modules will not be available.'));
    }

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'stupid_pagination' => true,
                'data' => $data,
                'top_bar' => [
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => [
                                [
                                    'url' => $baseurl . '/workflows/moduleIndex/type:all',
                                    'text' => __('All'),
                                    'active' => $indexType === 'all',
                                ],
                                [
                                    'url' => $baseurl . '/workflows/moduleIndex/type:action',
                                    'text' => __('Action'),
                                    'active' => $indexType === 'action',
                                ],
                                [
                                    'url' => $baseurl . '/workflows/moduleIndex/type:logic',
                                    'text' => __('Logic'),
                                    'active' => $indexType === 'logic',
                                ],
                            ]
                        ],
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'searchKey' => 'value',
                            'cancel' => [
                                'fa-icon' => 'times',
                                'title' => __('Remove filters'),
                                'onClick' => 'cancelSearch',
                            ]
                        ]
                    ]
                ],
                'fields' => $fields,
                'icon' => 'flag',
                'title' => __('Workflow Modules'),
                'description' => __('List the available modules that can be used by workflows'),
                'actions' => [
                    [
                        'title' => __('Enable'),
                        'icon' => 'play',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/enableModule',
                        'url_params_data_paths' => ['id'],
                        'postLinkConfirm' => __('Are you sure you want to enable this module?'),
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
                        'url' => $baseurl . '/workflows/disableModule',
                        'url_params_data_paths' => ['id'],
                        'postLinkConfirm' => __('Are you sure you want to disable this module?'),
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
                        'url' => $baseurl . '/workflows/moduleView',
                        'url_params_data_paths' => ['id'],
                        'icon' => 'eye',
                        'dbclickAction' => true,
                    ],
                ]
            ]
        ]
    ]);
