<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => 'CollectionElement.id',
            'data_path' => 'CollectionElement.id'
        ],
        [
            'name' => __('UUID'),
            'data_path' => 'CollectionElement.uuid'
        ],
        [
            'name' => __('Element'),
            'sort' => 'CollectionElement.element_type',
            'element' => 'model',
            'model_name' => 'CollectionElement.element_type',
            'model_id' => 'CollectionElement.element_uuid'
        ],
        [
            'name' => __('Element type'),
            'data_path' => 'CollectionElement.element_type'
        ],
        [
            'name' => __('Description'),
            'data_path' => 'CollectionElement.description'
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
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => empty($ajax) ? __('Collection element index') : false,
                'actions' => [
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/collectionElements/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'CollectionElement.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
