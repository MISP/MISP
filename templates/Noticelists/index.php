<?php
$fields = [
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id'
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name'
    ],
    [
        'name' => __('Expanded Name'),
        'sort' => 'expanded_name',
        'data_path' => 'expanded_name'
    ],
    [
        'name' => __('Ref'),
        'data_path' => 'ref'
    ],
    [
        'name' => __('Geographical area'),
        'data_path' => 'geographical_area',
        'element' => 'list'
    ],
    [
        'name' => __('Version'),
        'data_path' => 'version',
    ],
    [
        'name' => __('Enabled'),
        'data_path' => 'enabled',
        'element' => 'toggle',
        'url' => '/noticelists/toggleEnable',
        'url_params_vars' => [
            [
                'datapath' => [
                    'id'
                ]
            ]
        ],
        'requirement' => $loggedUser['Role']['perm_site_admin'],
    ],
    [
        'name' => __('Default'),
        'data_path' => 'enabled',
        'element' => 'boolean',
        'colors' => true,
        'requirement' => !$loggedUser['Role']['perm_site_admin'],
    ],
];


echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'children' => [
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
        'fields' => $fields,
        'title' => empty($ajax) ? __('Noticelists') : false,
        'actions' => [
            [
                'url' => '/noticelists/view',
                'url_params_data_paths' => ['id'],
                'icon' => 'eye'
            ],
        ]
    ]
]);
