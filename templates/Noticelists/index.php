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
        'requirement' => $isSiteAdmin,
    ],
    [
        'name' => __('Default'),
        'data_path' => 'enabled',
        'element' => 'boolean',
        'colors' => true,
        'requirement' => !$isSiteAdmin,
    ],
];


echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'pull' => 'right',
            'children' => [
                [
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'searchKey' => 'quickFilter',
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
