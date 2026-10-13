<?php
    App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
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
            'element' => 'custom',
            'function' => function (array $row) use ($baseurl) {
                $element = $row['CollectionElement'];
                if ($element['element_type'] === 'Value') {
                    return sprintf(
                        '<a href="%s/values/view/%s">%s</a>',
                        h($baseurl),
                        h(ValueUrlTool::encode($element['value'])),
                        h($element['value'])
                    );
                }
                return $this->element('genericElements/IndexTable/Fields/model', [
                    'row' => $row,
                    'field' => [
                        'model_name' => 'CollectionElement.element_type',
                        'model_id' => 'CollectionElement.element_uuid'
                    ]
                ]);
            }
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
