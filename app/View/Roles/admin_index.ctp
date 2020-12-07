<?php
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'Role.id',
            'data_path' => 'Role.id'
        ],
        [
            'name' => __('Default'),
            'data_path' => 'Role.default',
            'element' => 'toggle',
            'url' => '/admin/roles/set_default',
            'url_params_data_paths' => ['Role.id'],
            'checkbox_class' => 'defaultRoleCheckbox',
            'beforeHook' => "$('.defaultRoleCheckbox').prop('checked', false); $(this).prop('checked', true);"
        ],
        [
            'name' => __('Name'),
            'sort' => 'Role.name',
            'data_path' => 'Role.name'
        ]
    ];

    foreach ($permFlags as $k => $permFlag) {
        $fields[] = [
            'name' => Inflector::Humanize(substr($k, 5)),
            'sort' => 'Role.' . $k,
            'data_path' => 'Role.' . $k,
            'element' => 'boolean'
        ];
    }

    $fields[] = [
        'name' => __('Memory Limit'),
        'sort' => 'Role.memory_limit',
        'data_path' => 'Role.memory_limit',
        'decorator' => function($value) use ($default_memory_limit) {
            return empty($value) ? $default_memory_limit : h($value);
        }
    ];

    $fields[] = [
        'name' => __('Max execution time'),
        'sort' => 'Role.max_execution_time',
        'data_path' => 'Role.max_execution_time',
        'decorator' => function($value) use ($default_max_execution_time) {
            return (empty($value) ? $default_max_execution_time : h($value)) . '&nbsp;s';
        }
    ];

    $fields[] = [
        'name' => __('Searches / 15 mins'),
        'sort' => 'Role.rate_limit_count',
        'data_path' => 'Role.rate_limit_count',
        'decorator' => function($value)
        {
            return (empty($value) ? __('Unlimited') : h($value));
        }
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
                                    'text' => __('Add role'),
                                    'class' => 'btn btn-primary',
                                    'onClick' => 'openGenericModal',
                                    'onClickParams' => [
                                        sprintf(
                                            '%s/admin/roles/add',
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
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => empty($ajax) ? __('Roles') : false,
                'description' => empty($ajax) ? __('Instance specific permission roles.') : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/admin/roles/edit',
                        'url_params_data_paths' => array(
                            'Role.id'
                        ),
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/admin/roles/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'Role.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);
