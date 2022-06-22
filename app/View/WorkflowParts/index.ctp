<?php
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'WorkflowPart.id',
            'data_path' => 'WorkflowPart.id',
        ],
        [
            'name' => __('UUID'),
            'sort' => 'WorkflowPart.uuid',
            'data_path' => 'WorkflowPart.uuid',
        ],
        [
            'name' => __('Name'),
            'sort' => 'WorkflowPart.name',
            'data_path' => 'WorkflowPart.name',
        ],
        [
            'name' => __('Description'),
            'sort' => 'WorkflowPart.description',
            'data_path' => 'WorkflowPart.description',
        ],
        [
            'name' => __('Timestamp'),
            'sort' => 'WorkflowPart.timestamp',
            'data_path' => 'WorkflowPart.timestamp',
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
                                    'fa-icon' => 'plus',
                                    'text' => __('Import Workflow Part'),
                                    'class' => 'btn-primary modal-open',
                                    'url' => "$baseurl/workflowParts/import",
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
                'title' => __('Workflow Parts'),
                'description' => __('You can create re-use workflow parts in your workflows'),
                'actions' => [
                    [
                        'url' => $baseurl . '/workflowParts/view',
                        'url_params_data_paths' => ['WorkflowPart.id'],
                        'icon' => 'eye',
                        'dbclickAction' => true,
                    ],
                    [
                        'url' => $baseurl . '/workflowParts/edit',
                        'url_params_data_paths' => ['WorkflowPart.id'],
                        'icon' => 'edit',
                    ],
                    [
                        'url' => $baseurl . '/workflowParts/export',
                        'url_params_data_paths' => ['WorkflowPart.id'],
                        'title' => __('Export Workflow Part'),
                        'icon' => 'download',
                    ],
                    [

                        'onclick' => sprintf(
                        'openGenericModal(\'%s/workflowParts/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'WorkflowPart.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);
