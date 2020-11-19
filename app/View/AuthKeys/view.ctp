<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Auth key view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'AuthKey.id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'AuthKey.uuid',
            ],
            [
                'key' => __('Auth key'),
                'path' => 'AuthKey',
                'type' => 'authkey'
            ],
            [
                'key' => __('Created'),
                'path' => 'AuthKey.created',
                'type' => 'datetime'
            ],
            [
                'key' => __('Expiration'),
                'path' => 'AuthKey.expiration',
                'type' => 'expiration'
            ],
            [
                'key' => __('User'),
                'path' => 'User.id',
                'pathName' => 'User.email',
                'model' => 'users',
                'type' => 'model'
            ],
            [
                'key' => __('Comment'),
                'path' => 'AuthKey.comment'
            ]
        ],
        'children' => [
        ]
    ]
);
