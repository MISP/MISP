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
                            'text' => __('Add organisation'),
                            'popover_url' => '/organisations/add',
                            'button' => [
                                'icon' => 'plus',
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
                'name' => __('Members'),
                'data_path' => 'user_count',
                'url' => '/users/index/?Organisations.id={{url_data}}',
                'url_data_path' => 'id'
            ],
            [
                'name' => __('URL'),
                'sort' => 'url',
                'class' => 'short',
                'data_path' => 'url',
            ],
            [
                'name' => __('Nationality'),
                'data_path' => 'nationality',
                'sort' => 'nationality',
            ],
            [
                'name' => __('Sector'),
                'data_path' => 'sector',
                'sort' => 'sector',
            ],
            [
                'name' => __('Type'),
                'data_path' => 'type',
                'sort' => 'type',
            ],
            /*
            [
                'name' => __('Tags'),
                'data_path' => 'tags',
                'element' => 'tags',
            ],
            */
        ],
        'primary_id_path' => 'id',
        'title' => __('Organisation Index'),
        'description' => __('A list of organisations known to your MISP instance. This list can get populated either directly, by adding new organisations or by fetching them from trusted remote sources.'),
        'actions' => [
            [
                'url' => '/organisations/view',
                'url_params_data_paths' => ['id'],
                'icon' => 'eye',
            ],
            [
                'open_modal' => '/organisations/edit/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'edit',
                'requirement' => $loggedUser['Role']['perm_admin']
            ],
            [
                'open_modal' => '/organisations/delete/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'trash',
                'requirement' => $loggedUser['Role']['perm_admin']
            ],
        ]
    ]
]);
echo '</div>';
?>
