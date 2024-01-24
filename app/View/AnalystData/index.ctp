<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => $modelSelection . '.id',
            'data_path' => $modelSelection . '.id'
        ],
        [
            'name' => __('UUID'),
            'data_path' => $modelSelection . '.uuid'
        ],
        [
            'name' => __('Parent Object Type'),
            'sort' => $modelSelection . '.object_type',
            'data_path' => $modelSelection . '.object_type'
        ],
        [
            'name' => __('Target Object'),
            'sort' => $modelSelection . '.object_type',
            'data_path' => $modelSelection . '.object_uuid'
        ],
        [
            'name' => __('Creator org'),
            'data_path' => $modelSelection . '.orgc_uuid'
        ],
        [
            'name' => __('Created'),
            'sort' => $modelSelection . '.created',
            'data_path' => $modelSelection . '.created'
        ],
        [
            'name' => __('Modified'),
            'sort' => $modelSelection . '.modified',
            'data_path' => $modelSelection . '.modified'
        ],
        [
            'name' => __('Distribution'),
            'sort' => $modelSelection . '.distribution',
            'data_path' => $modelSelection . '.distribution'
        ]
    ];

    if ($modelSelection === 'Note') {
        $fields = array_merge($fields,
            [
                [
                    'name' => __('Language'),
                    'sort' => $modelSelection . '.language',
                    'data_path' => $modelSelection . '.language'
                ],
                [
                    'name' => __('Note'),
                    'sort' => $modelSelection . '.note',
                    'data_path' => $modelSelection . '.note'
                ]
            ]
        );
    } else if ($modelSelection === 'Opinion') {
        $fields = array_merge($fields,
            [
            ]
        );
    
    } else if ($modelSelection === 'Relationship') {
    
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
                            'children' => [
                                [
                                    'active' => $modelSelection === 'Note',
                                    'url' => sprintf('%s/analyst_data/index/Note', $baseurl),
                                    'text' => __('Note'),
                                ],
                                [
                                    'active' => $modelSelection === 'Opinion',
                                    'class' => 'defaultContext',
                                    'url' => sprintf('%s/analyst_data/index/Opinion', $baseurl),
                                    'text' => __('Opinion'),
                                ],
                                [
                                    'active' => $modelSelection === 'Relationship',
                                    'url' => sprintf('%s/analyst_data/index/Relationship', $baseurl),
                                    'text' => __('Relationship'),
                                ],
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
                'title' => empty($ajax) ? __('%s index', Inflector::pluralize($modelSelection)) : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/analystData/view/' . $modelSelection . '/',
                        'url_params_data_paths' => [$modelSelection . '.id'],
                        'icon' => 'eye'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/analystData/edit/' . $modelSelection . '/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => $modelSelection . '.id',
                        'title' => __('Edit %s', $modelSelection),
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/analystData/delete/' . $modelSelection . '/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => $modelSelection . '.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
