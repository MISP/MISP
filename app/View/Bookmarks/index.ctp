<?php
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'Bookmark.id',
            'data_path' => 'Bookmark.id',
        ],
        [
            'name' => __('Organisation'),
            'sort' => 'Bookmark.org_id',
            'element' => 'org',
            'data_path' => 'Organisation'
        ],
        [
            'name' => __('User'),
            'sort' => 'User.email',
            'data_path' => 'User.email',
        ],
        [
            'name' => __('Name'),
            'sort' => 'Bookmark.name',
            'data_path' => 'Bookmark.name',
        ],
        [
            'name' => __('URL'),
            'sort' => 'Bookmark.url',
            'data_path' => 'Bookmark.url',
        ],
        [
            'name' => __('Comment'),
            'sort' => 'Bookmark.comment',
            'data_path' => 'Bookmark.comment',
        ],
        [
            'name' => __('Exposed to Organsation'),
            'title' => __('Is this bookmark exposed to all users belonging to the bookmark\'s organisation'),
            'sort' => 'Bookmark.exposed_to_org',
            'data_path' => 'Bookmark.exposed_to_org',
            'element' => 'boolean',
            'colors' => true,
            'class' => 'short',
        ],
    ];

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'children' => [
                        [
                            'children' => [
                                [
                                    'text' => __('All Bookmarks'),
                                    'active' => $scope === 'all',
                                    'url' => $baseurl . '/bookmarks/index'
                                ],
                                [
                                    'text' => __('My Bookmarks'),
                                    'active' => $scope === 'mine',
                                    'url' => $baseurl . '/bookmarks/index/scope:mine'
                                ],
                            ]
                        ],
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => __('Bookmarks'),
                'description' => __('You can create bookmarks that will be added in the navigation top bar. Each bookmark can be exposed to all users from the organisation.'),
                'actions' => [
                    [
                        'url' => $baseurl . '/bookmarks/view',
                        'url_params_data_paths' => ['Bookmark.id'],
                        'icon' => 'eye',
                        'dbclickAction' => true,
                        'title' => __('View'),
                    ],
                    [
                        'url' => $baseurl . '/bookmarks/edit',
                        'url_params_data_paths' => ['Bookmark.id'],
                        'icon' => 'edit',
                        'title' => __('Edit'),
                        'complex_requirement' => [
                            'function' => function($row) use ($me) {
                                return $me['Role']['perm_site_admin'] ||
                                        $me['id'] == $row['Bookmark']['user_id'] ||
                                        ($me['org_id'] == $row['Bookmark']['org_id'] && $me['Role']['perm_admin']);
                            },
                        ],
                    ],
                    [
                        'class' => 'modal-open',
                        'url' => $baseurl . '/bookmarks/delete/',
                        'url_params_data_paths' => 'Bookmark.id',
                        'icon' => 'trash',
                        'title' => __('Delete'),
                        'complex_requirement' => [
                            'function' => function($row) use ($me) {
                                return $me['Role']['perm_site_admin'] ||
                                        $me['id'] == $row['Bookmark']['user_id'] ||
                                        ($me['org_id'] == $row['Bookmark']['org_id'] && $me['Role']['perm_admin']);
                            },
                        ],
                    ]
                ]
            ]
        ]
    ]);
