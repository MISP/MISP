<?php
$fields = [
    [
        'name' => __('Owner Org'),
        'sort' => 'org.name',
        'element' => 'org',
        'data_path' => 'org',
        'class' => 'short',
    ],
    [
        'name' => __('Creator Org'),
        'sort' => 'orgc.name',
        'element' => 'org',
        'data_path' => 'orgc',
        'class' => 'short',
    ],
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id'
    ],
    //clusters,
    //tags,
    [
        'name' => __('#Attr.'),
        'data_path' => 'attribute_count',
        'sort' => 'attribute_count',
    ],
    [
        'name' => __('Info'),
        'sort' => 'info',
        'data_path' => 'info'
    ],
    [
        'name' => __('Creator User'),
        'sort' => 'user.email',
        'data_path' => 'user.email'
    ],
    [
        'name' => __('Date'),
        'sort' => 'timestamp',
        'data_path' => 'timestamp'
    ],
    [
        'name' => __('Distribution'),
        'sort' => 'distribution',
        'data_path' => 'distribution'
    ],
];


echo $this->element(
    'genericElements/IndexTable/index_table',
    [
        'data' => [
            'data' => $events,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'context_filters',
                    ]
                ]
            ],
            'fields' => $fields,
            'title' => empty($ajax) ? __('Events') : false,
            'actions' => [
                [
                    'url' => '/events/view',
                    'url_params_data_paths' => ['id'],
                    'icon' => 'edit'
                ],
                [
                    'url' => '/events/delete',
                    'url_params_data_paths' => ['id'],
                    'icon' => 'trash'
                ],
                [
                    'url' => '/events/view',
                    'url_params_data_paths' => ['id'],
                    'icon' => 'eye'
                ],
            ]
        ]
    ]
);
