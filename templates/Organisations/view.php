<?php
echo $this->element(
    '/genericElements/SingleViews/single_view',
    [
        'title' => __('Organisation View'),
        'data' => $entity,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'id'
            ],
            [
                'key' => __('Name'),
                'path' => 'name'
            ],
            [
                'key' => __('UUID'),
                'path' => 'uuid'
            ],
            [
                'key' => __('URL'),
                'path' => 'url'
            ],
            [
                'key' => __('Nationality'),
                'path' => 'nationality'
            ],
            [
                'key' => __('Sector'),
                'path' => 'sector'
            ],
            [
                'key' => __('Type'),
                'path' => 'type'
            ],
            [
                'key' => __('Contacts'),
                'path' => 'contacts'
            ]
        ],
        'combinedFieldsView' => false,
        'children' => [
            [
                'url' => '/Users/index?Organisations.id={{0}}',
                'url_params' => ['id'],
                'title' => __('Users')
            ]
        ]
    ]
);
