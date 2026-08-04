<?php
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'WorkflowBlueprint.id',
            'data_path' => 'WorkflowBlueprint.id',
        ],
        [
            'name' => __('UUID'),
            'sort' => 'WorkflowBlueprint.uuid',
            'data_path' => 'WorkflowBlueprint.uuid',
        ],
        [
            'name' => __('Name'),
            'sort' => 'WorkflowBlueprint.name',
            'data_path' => 'WorkflowBlueprint.name',
        ],
        [
            'name' => __('Default'),
            'sort' => 'WorkflowBlueprint.default',
            'data_path' => 'WorkflowBlueprint.default',
            'element' => 'boolean',
            'colors' => true,
            'class' => 'short',
        ],
        [
            'name' => __('Description'),
            'sort' => 'WorkflowBlueprint.description',
            'data_path' => 'WorkflowBlueprint.description',
        ],
        [
            'name' => __('Timestamp'),
            'sort' => 'WorkflowBlueprint.timestamp',
            'data_path' => 'WorkflowBlueprint.timestamp',
            'element' => 'datetime',
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
                                    'text' => __('Import Workflow Blueprint'),
                                    'class' => 'btn-primary modal-open',
                                    'url' => "$baseurl/workflowBlueprints/import",
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
                'title' => __('Workflow Blueprints'),
                'description' => __('You can create re-use workflow blueprints in your workflows'),
                'actions' => [
                    [
                        'url' => $baseurl . '/workflowBlueprints/view',
                        'url_params_data_paths' => ['WorkflowBlueprint.id'],
                        'icon' => 'eye',
                        'dbclickAction' => true,
                        'title' => __('View'),
                    ],
                    [
                        'url' => $baseurl . '/workflowBlueprints/edit',
                        'url_params_data_paths' => ['WorkflowBlueprint.id'],
                        'icon' => 'edit',
                        'title' => __('Edit'),
                    ],
                    [
                        'url' => $baseurl . '/workflowBlueprints/export',
                        'url_params_data_paths' => ['WorkflowBlueprint.id'],
                        'title' => __('Export Workflow Blueprint'),
                        'icon' => 'download',
                    ],
                    [
                        'class' => 'modal-open',
                        'url' => $baseurl . '/workflowBlueprints/delete/',
                        'url_params_data_paths' => 'WorkflowBlueprint.id',
                        'icon' => 'trash',
                        'title' => __('Delete'),
                    ]
                ]
            ]
        ]
    ]);
