<?php
$fields = [
    [
        'name' => __('Id'),
        'sort' => 'Noticelist.id',
        'data_path' => 'Noticelist.id'
    ],
    [
        'name' => __('Name'),
        'sort' => 'Noticelist.name',
        'data_path' => 'Noticelist.name'
    ],
    [
        'name' => __('Expanded Name'),
        'sort' => 'Noticelist.expanded_name',
        'data_path' => 'Noticelist.expanded_name'
    ],
    [
        'name' => __('ref'),
        'data_path' => 'Noticelist.ref',
        'element' => 'links'
    ],
    [
        'name' => __('geographical_area'),
        'data_path' => 'Noticelist.geographical_area',
        'element' => 'list'
    ],
    [
        'name' => __('version'),
        'data_path' => 'Noticelist.version',
    ],
    [
        'name' => __('enabled'),
        'data_path' => 'Noticelist.enabled',
        'element' => 'toggle',
        'url' => '/admin/noticelists/enableNoticelist',
        'url_params_data_paths' => ['Noticelist.id'],
        'requirement' => $isSiteAdmin
    ]
];


echo $this->element('genericElements/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'pull' => 'right',
            ],
            'fields' => $fields,
            'title' => empty($ajax) ? __('Noticelists') : false,
            // 'description' => empty($ajax) ? __('You can connect your MISP to one or several Cerebrate instances to act as lookup directories for organisation and sharing group information.') : false,
            'actions' => [
                [
                    'url' => $baseurl . '/noticelists/view',
                    'url_params_data_paths' => ['Noticelist.id'],
                    'icon' => 'eye'
                ],
            ]
        ]
    ]
]);
