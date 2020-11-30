<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => 'Cerebrate.id',
            'data_path' => 'Cerebrate.id'
        ],
        [
            'name' => __('Owner Org'),
            'sort' => 'Organisation',
            'data_path' => 'Organisation',
            'element' => 'org'
        ],
        [
            'name' => __('Name'),
            'sort' => 'Cerebrate.name',
            'data_path' => 'Cerebrate.name'
        ],
        [
            'name' => __('URL'),
            'sort' => 'Cerebrate.url',
            'data_path' => 'Cerebrate.url'
        ],
        [
            'name' => __('Description'),
            'sort' => 'Cerebrate.description',
            'data_path' => 'Cerebrate.description'
        ],
        [
            'name' => __('Pull Orgs'),
            'sort' => 'Cerebrate.pull_orgs',
            'data_path' => 'Cerebrate.pull_orgs',
            'element' => 'boolean'
        ],
        [
            'name' => __('Pull SGs'),
            'sort' => 'Cerebrate.pull_sharing_groups',
            'data_path' => 'Cerebrate.pull_sharing_groups',
            'element' => 'boolean'
        ]
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
                                    'text' => __('Add Cerebrate'),
                                    'class' => 'btn btn-primary',
                                    'onClick' => 'openGenericModal',
                                    'onClickParams' => [
                                        sprintf(
                                            '%s/cerebrates/add',
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
                'title' => empty($ajax) ? __('Linked Cerebrates') : false,
                'description' => empty($ajax) ? __('You can connect your MISP to one or several Cerebrate instances to act as lookup directories for organisation and sharing group information.') : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/cerebrates/view',
                        'url_params_data_paths' => ['Cerebrate.id'],
                        'icon' => 'eye'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/cerebrates/pull_orgs/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'Cerebrate.id',
                        'title' => __('Pull all organisations'),
                        'icon' => 'arrow-circle-down'
                    ],
                    [
                        'url' => $baseurl . '/cerebrates/edit',
                        'url_params_data_paths' => ['Cerebrate.id'],
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/cerebrates/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'Cerebrate.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
