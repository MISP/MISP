<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => 'CorrelationRule.id',
            'data_path' => 'CorrelationRule.id'
        ],
        [
            'name' => __('Name'),
            'sort' => 'CorrelationRule.name',
            'data_path' => 'CorrelationRule.name'
        ],
        [
            'name' => __('UUID'),
            'data_path' => 'CorrelationRule.uuid'
        ],
        [
            'name' => __('Comment'),
            'data_path' => 'CorrelationRule.comment'
        ],
        [
            'name' => __('Type'),
            'sort' => 'CorrelationRule.selector_type',
            'data_path' => 'CorrelationRule.selector_type'
        ],
        [
            'name' => __('Selectors'),
            'data_path' => 'CorrelationRule.selector_list',
            'element' => 'json'
        ],
        [
            'name' => __('Created'),
            'sort' => 'CorrelationRule.created',
            'data_path' => 'CorrelationRule.created',
            'element' => 'time'
        ],
        [
            'name' => __('Modified'),
            'sort' => 'CorrelationRule.timestamp',
            'data_path' => 'CorrelationRule.timestamp',
            'element' => 'time'
        ]
    ];

    $typeChildElements = [

    ];
    foreach ($dropdownData['selector_types'] as $selector_type => $description) {
        $typeChildElements[] = [
            'url' => $baseurl . '/correlationRules/index/selector_type:' . $selector_type,
            'text' => $description,
        ];
    }

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => $typeChildElements
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
                'title' => empty($ajax) ? __('Correlation rules index') : false,
                'actions' => [
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/correlationRules/edit/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'CorrelationRule.id',
                        'title' => __('Edit Correlation Rule'),
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/correlationRules/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'title' => __('Delete Correlation Rule'),
                        'onclick_params_data_path' => 'CorrelationRule.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
