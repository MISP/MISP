<?php
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'children' => [
                [
                    'type' => 'simple',
                    'children' => [
                        'data' => [
                            'type' => 'simple',
                            'text' => __('Update templates'),
                            'popover_url' => '/object-templates/update',
                            'button' => [
                                'icon' => 'refresh',
                            ]
                        ]
                    ]
                ],
                [
                    'type' => 'context_filters',
                ],
                [
                    'type' => 'search',
                    'button' => __('Search'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchKey' => 'value',
                    'allowFilering' => true
                ],
                [
                    'type' => 'table_action',
                    'table_setting_id' => 'organisation_index',
                ]
            ]
        ],
        'fields' => [
            [
                'name' => '#',
                'sort' => 'id',
                'class' => 'short',
                'data_path' => 'id',
            ],
            [
                'name' => __('Name'),
                'class' => 'short',
                'data_path' => 'name',
                'sort' => 'name',
            ],
            [
                'name' => __('UUID'),
                'sort' => 'uuid',
                'class' => 'short',
                'data_path' => 'uuid',
            ],
            [
                'name' => __('Organisation'),
                'sort' => 'Organisation.name',
                'element' => 'org',
                'data_path' => 'Organisation',
                'class' => 'short',
            ],
            [
                'name' => __('Version'),
                'data_path' => 'version',
                'sort' => 'version',
            ],
            [
                'name' => __('Meta-Category'),
                'data_path' => 'meta_category',
                'sort' => 'meta_category',
            ],
            [
                'name' => __('Description'),
                'data_path' => 'description',
                'sort' => 'Description',
            ],
            [
                'name' => __('Requirements'),
                'data_path' => 'requirements',
                'element' => 'array'
            ],
        ],
        'primary_id_path' => 'id',
        'title' => __('Object Templates Index'),
        'actions' => [
            [
                'url' => '/object-templates/view',
                'url_params_data_paths' => ['id'],
                'icon' => 'eye',
            ],
            [
                'open_modal' => '/object-templates/edit/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'refresh',
                'requirement' => $loggedUser['Role']['perm_admin']
            ],
            [
                'open_modal' => '/object-templates/delete/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'trash',
                'requirement' => $loggedUser['Role']['perm_admin']
            ],
        ]
    ]
]);
echo '</div>';
?>
