<?php
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
                                    'text' => __('Add SharingGroupBlueprint'),
                                    'class' => 'btn btn-primary',
                                    'url' => sprintf(
                                        '%s/SharingGroupBlueprints/add',
                                        $baseurl
                                    )
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
                'fields' => [
                    [
                        'name' => __('Id'),
                        'sort' => 'SharingGroupBlueprint.id',
                        'data_path' => 'SharingGroupBlueprint.id'
                    ],
                    [
                        'name' => __('Owner organisation'),
                        'sort' => 'Organisation',
                        'data_path' => 'Organisation',
                        'element' => 'org'
                    ],
                    [
                        'name' => __('Name'),
                        'sort' => 'SharingGroupBlueprint.name',
                        'data_path' => 'SharingGroupBlueprint.name'
                    ],
                    [
                        'name' => __('SharingGroup'),
                        'sort' => 'SharingGroupBlueprint.sharing_group_id',
                        'data_path' => 'SharingGroupBlueprint.sharing_group_id',
                        'element' => 'custom',
                        'function' => function ($row) use ($baseurl) {
                            if (!empty($row['SharingGroupBlueprint']['sharing_group_id'])) {
                                if (!empty($row['SharingGroup'])) {
                                    echo sprintf(
                                        '<a href="%s/sharingGroups/view/%s" title="%s">#%s: %s</a> %s',
                                        $baseurl,
                                        h($row['SharingGroup']['id']),
                                        h($row['SharingGroup']['releasability']),
                                        h($row['SharingGroup']['id']),
                                        h($row['SharingGroup']['name']),
                                        sprintf(
                                            '<a href="#" class="black fas fa-trash" onClick="openGenericModal(\'%s/sharing_group_blueprints/detach/%s\');"></a>',
                                            $baseurl,
                                            h($row['SharingGroupBlueprint']['id'])
                                        )
                                    );
                                }
                            } else {
                                echo '&nbsp;';
                            }
                        },
                    ],
                    [
                        'name' => __('Rules'),
                        'sort' => 'SharingGroupBlueprint.rules',
                        'data_path' => 'SharingGroupBlueprint.rules',
                        'element' => 'json'
                    ]
                ],
                'title' => empty($ajax) ? __('Sharing Group Blueprints') : false,
                'description' => empty($ajax) ? __('Sharing Group Blueprints are blueprints for the creation of sharing groups') : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/SharingGroupBlueprints/view',
                        'url_params_data_paths' => ['SharingGroupBlueprint.id'],
                        'icon' => 'eye'
                    ],
                    [
                        'url' => $baseurl . '/SharingGroupBlueprints/edit',
                        'url_params_data_paths' => ['SharingGroupBlueprint.id'],
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/SharingGroupBlueprints/execute/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'SharingGroupBlueprint.id',
                        'icon' => 'recycle',
                        'title' => __('(Re)generate sharing group based on blueprint')
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/SharingGroupBlueprints/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'SharingGroupBlueprint.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
