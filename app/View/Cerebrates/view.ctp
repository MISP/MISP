<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Cerebrate view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Id'),
                'path' => 'Cerebrate.id'
            ],
            [
                'key' => __('Name'),
                'path' => 'Cerebrate.name'
            ],
            [
                'key' => __('URL'),
                'path' => 'Cerebrate.url',
                'url' => '{{0}}',
                'url_vars' => ['Cerebrate.url']
            ],
            [
                'key' => __('Owner Organisation'),
                'path' => 'Cerebrate.org_id',
                'pathName' => 'Organisation.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Description'),
                'path' => 'Cerebrate.description'
            ],
        ],
        'side_panels' => [
            [
                'type' => 'logo',
                'source' => '/img/cerebrate.png',
                'url' => 'https://github.com/cerebrate-project/cerebrate',
                'title' => __('The Cerebrate Project'),
                'img' => [
                    'css' => [
                        'width' => '150px',
                        'height' => '150px'
                    ],
                ],
                'div' => [
                    'css' => [
                        'text-align' => 'right'
                    ]
                ]
            ]
        ],
        'children' => [
            [
                'url' => '/cerebrates/preview_orgs/{{0}}/',
                'url_params' => ['Cerebrate.id'],
                'title' => __('Organisations'),
                'elementId' => 'preview_orgs_container'
            ]
        ]
    ]
);
