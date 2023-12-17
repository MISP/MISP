<?php
echo $this->element(
    '/genericElements/SingleViews/single_view',
    [
        'title' => __('Cerebrate {0}', h($entity->name)),
        'data' => $entity,
        'fields' => [
            [
                'key' => __('Id'),
                'path' => 'id'
            ],
            [
                'key' => __('Name'),
                'path' => 'name'
            ],
            [
                'key' => __('URL'),
                'path' => 'url',
                'url' => '{{0}}',
                'url_vars' => ['url']
            ],
            [
                'key' => __('Owner Organisation'),
                'path' => 'org_id',
                'pathName' => 'Organisation.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Description'),
                'path' => 'description'
            ],
        ],
        // 'side_panels' => [  // FIXME chri missing side-panel
        //     [
        //         'type' => 'logo',
        //         'source' => '/img/cerebrate.png',
        //         'url' => 'https://github.com/cerebrate-project/cerebrate',
        //         'title' => __('The Cerebrate Project'),
        //         'img' => [
        //             'css' => [
        //                 'width' => '150px',
        //                 'height' => '150px'
        //             ],
        //         ],
        //         'div' => [
        //             'css' => [
        //                 'text-align' => 'right'
        //             ]
        //         ]
        //     ]
        // ],
        'children' => [
            [
                'url' => '/cerebrates/preview_orgs/{{0}}/',
                'url_params' => ['id'],
                'title' => __('Organisations'),
                // FIXME chri - 'elementId' => 'preview_orgs_container'
            ],
            [
                'url' => '/cerebrates/preview_sharing_groups/{{0}}/',
                'url_params' => ['id'],
                'title' => __('Sharing Groups'),
                // FIXME chri - 'elementId' => 'preview_sgs_container' FIXME chri
            ],
        ]
    ]
);
