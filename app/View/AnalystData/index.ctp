<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => $modelSelection . '.id',
            'data_path' => $modelSelection . '.id'
        ],
        [
            'name' => __('OrgC'),
            'element' => 'org',
            'data_path' => $modelSelection . '.Orgc'
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
            'element' => 'distribution_levels',
            'sort' => $modelSelection . '.distribution',
            'class' => 'short',
            'data_path' => $modelSelection . '.distribution',
            'sg_path' => $modelSelection . '.SharingGroup',
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
                [
                    'name' => __('Comment'),
                    'data_path' => $modelSelection . '.comment'
                ],
                [
                    'name' => __('Opinion'),
                    'data_path' => $modelSelection . '.opinion',
                    'element' => 'opinion_scale',
                ],
            ]
        );
    
    } else if ($modelSelection === 'Relationship') {
        $fields = array_merge($fields,
            [
                [
                    'name' => __('Related Object'),
                    'element' => 'custom',
                    'function' => function (array $row) use ($baseurl, $modelSelection) {
                        $path = Inflector::pluralize(strtolower($row[$modelSelection]['related_object_type']));
                        return sprintf(
                            '<span class="bold">%s</span>: <a href="%s/%s/view/%s">%s</a>',
                            h($row[$modelSelection]['related_object_type']),
                            h($baseurl),
                            h($path),
                            h($row[$modelSelection]['related_object_uuid']),
                            h($row[$modelSelection]['related_object_uuid'])
                        );
                    }
                ],
                [
                    'name' => __('Relationship_type'),
                    'sort' => $modelSelection . '.relationship_type',
                    'data_path' => $modelSelection . '.relationship_type'
                ],
            ]
        );
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
                        'url' => $baseurl . '/analystData/view/' . $modelSelection,
                        'url_params_data_paths' => [$modelSelection . '.id'],
                        'icon' => 'eye',
                        'dbclickAction' => true,
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/analystData/edit/' . $modelSelection . '/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => $modelSelection . '.id',
                        'title' => __('Edit %s', $modelSelection),
                        'icon' => 'edit',
                        'complex_requirement' => function($item) use ($modelSelection) {
                            return !empty($item[$modelSelection]['_canEdit']);
                        }
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/analystData/delete/' . $modelSelection . '/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => $modelSelection . '.id',
                        'icon' => 'trash',
                        'complex_requirement' => function($item) use ($modelSelection) {
                            return !empty($item[$modelSelection]['_canEdit']);
                        }
                    ]
                ]
            ]
        ]
    ]);

?>
