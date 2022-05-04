<?php
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'Workflow.id',
            'data_path' => 'Workflow.id'
        ],
        [
            'name' => __('Owner Org'),
            'sort' => 'Organisation',
            'data_path' => 'Organisation',
            'element' => 'org'
        ],
        [
            'name' => __('Name'),
            'sort' => 'Workflow.name',
            'data_path' => 'Workflow.name'
        ],
        [
            'name' => __('Description'),
            'sort' => 'Workflow.description',
            'data_path' => 'Workflow.description'
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
                        'url' => $baseurl . '/workflows/view/',
                        'url_params_data_paths' => ['Workflow.id'],
                        'icon' => 'eye'
                    ],
                    [
                        'url' => $baseurl . '/workflows/editor/',
                        'url_params_data_paths' => ['Workflow.id'],
                        'icon' => 'code'
                    ],
                    [
                        'url' => $baseurl . '/workflows/edit',
                        'url_params_data_paths' => ['Workflow.id'],
                        'icon' => 'edit'
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
