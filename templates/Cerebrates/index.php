<?php
$fields = [
    [
        'name' => __('ID'),
        'sort' => 'id',
        'class' => 'short',
        'data_path' => 'id',
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Organisation',
        'data_path' => 'Organisation',
        'element' => 'org',
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name',
    ],
    [
        'name' => __('URL'),
        'sort' => 'url',
        'data_path' => 'url',
    ],
    [
        'name' => __('Description'),
        'sort' => 'description',
        'data_path' => 'description',
    ],
    [
        'name' => __('Pull Orgs'),
        'sort' => 'pull_orgs',
        'data_path' => 'pull_orgs',
        'element' => 'boolean',
    ],
    [
        'name' => __('Pull SGs'),
        'sort' => 'pull_sharing_groups',
        'data_path' => 'pull_sharing_groups',
        'element' => 'boolean',
    ],
];

echo $this->element(
    'genericElements/IndexTable/index_table',
    [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'simple',
                        'children' => [
                            'data' => [
                                'type' => 'simple',
                                'icon' => 'plus',
                                'text' => __('Add Cerebrate'),
                                'class' => 'btn btn-primary',
                                'popover_url' => '/cerebrates/add',
                                'button' => [
                                    'icon' => 'plus',
                                ],
                            ],
                        ],
                    ],
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value',
                        'allowFilering' => true,
                    ],
                    [
                        'type' => 'table_action',
                    ],
                ],
            ],
            'fields' => $fields,
            'title' => __('Linked Cerebrates'),
            'description' => __('You can connect your MISP to one or several Cerebrate instances to act as lookup directories for organisation and sharing group information.'),
            'actions' => [
                [
                    'url' => '/cerebrates/view',
                    'url_params_data_paths' => ['id'],
                    'icon' => 'eye',
                ],
                [
                    'open_modal' => '/cerebrates/pull_orgs/[onclick_params_data_path]',
                    'onclick_params_data_path' => 'id',
                    'title' => __('Pull all organisations'),
                    'icon' => 'arrow-circle-down',
                ],
                [
                    'open_modal' => '/cerebrates/pull_sgs/[onclick_params_data_path]',
                    'onclick_params_data_path' => 'id',
                    'title' => __('Pull all sharing groups'),
                    'icon' => 'arrow-circle-down',
                ],
                [
                    'open_modal' => '/cerebrates/edit/[onclick_params_data_path]',
                    'modal_params_data_path' => 'id',
                    'icon' => 'edit',
                ],
                [
                    'open_modal' => '/cerebrates/delete/[onclick_params_data_path]',
                    'modal_params_data_path' => 'id',
                    'icon' => 'trash',
                ],
            ],
        ],
    ]
);
