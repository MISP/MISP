<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => 'Collection.id',
            'data_path' => 'Collection.id'
        ],
        [
            'name' => __('Name'),
            'sort' => 'Collection.name',
            'data_path' => 'Collection.name'
        ],
        [
            'name' => __('Organisation'),
            'sort' => 'Orgc.name',
            'data_path' => 'Orgc',
            'element' => 'org'
        ],
        [
            'name' => __('Elements'),
            'sort' => 'Collection.element_count',
            'data_path' => 'Collection.element_count'
        ],
        [
            'name' => __('UUID'),
            'data_path' => 'Collection.uuid'
        ],
        [
            'name' => __('Type'),
            'data_path' => 'Collection.type'
        ],
        [
            'name' => __('Created'),
            'sort' => 'Collection.created',
            'data_path' => 'Collection.created'
        ],
        [
            'name' => __('Modified'),
            'sort' => 'Collection.modified',
            'data_path' => 'Collection.modified'
        ],
        [
            'name' => __('Distribution'),
            'sort' => 'distribution',
            'data_path' => 'Collection.distribution',
            'element' => 'distribution_levels'
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
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => empty($ajax) ? __('Collections index') : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/collections/view',
                        'url_params_data_paths' => ['Collection.id'],
                        'icon' => 'eye'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/collections/edit/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'Collection.id',
                        'title' => __('Edit Collection'),
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/collections/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'Collection.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
