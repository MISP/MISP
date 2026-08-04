<?php
$this->set('headerTitle', __('Users'));

$canAdmin = !empty($isSiteAdmin) || !empty($me['Role']['perm_admin']);

$headerActions = [];

$headerActions[] = [
    'type'  => 'navigate',
    'label' => __('View registrations'),
    'icon'  => 'person-circle-plus',
    'url'   => $baseurl . '/users/registrations',
];


if ($canAdmin) {
    $headerActions[] = [
        'type'  => 'modal',
        'label' => __('Contact users'),
        'icon'  => 'envelope',
        'url'   => $baseurl . '/admin/users/email',
        'class' => 'btn btn-outline-primary',
    ];
}

$headerActions[] = [
    'type'  => 'modal',
    'label' => __('Add user'),
    'icon'  => 'plus',
    'url'   => $baseurl . '/admin/users/add',
];

$this->set('headerActions', $headerActions);

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'User.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'User.id',
        'data_path' => 'User.id',
        'element' => 'id',
        'url' => $baseurl . '/admin/users/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Email'),
        'sort' => 'User.email',
        'data_path' => 'User.email',
        'id_path' => 'User.id',
        'element' => 'user_email',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'User.org_id',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Role'),
        'sort' => 'User.role_id',
        'data_path' => 'Role',
        'element' => 'role',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('TOTP'),
        'sort' => 'User.totp',
        'data_path' => 'User.totp',
        'element' => 'flag',
        'requirement' => empty(Configure::read('Security.otp_disabled')),
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('PGP'),
        'sort' => 'User.gpgkey',
        'data_path' => 'User.gpgkey',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Last login'),
        'sort' => 'User.current_login',
        'data_path' => 'User.current_login',
        'element' => 'datetime',
        'empty' => __('Never'),
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Created'),
        'sort' => 'User.date_created',
        'data_path' => 'User.date_created',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Status'),
        'sort' => 'User.disabled',
        'data_path' => 'User.disabled',
        'element' => 'user_status',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'User.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/admin/users/view/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/admin/users/edit/%id%',
                'requirement' => $canAdmin,
            ],
            [
                'type' => 'modal',
                'label' => __('Send email'),
                'icon' => 'envelope',
                'url' => $baseurl . '/admin/users/quickEmail/%id%',
                'requirement' => $canAdmin,
            ],
            [
                'type' => 'modal',
                'label' => __('Create new credentials'),
                'icon' => 'key',
                'size' => 'lg',
                'url' => $baseurl . '/users/initiatePasswordReset/%id%',
                // perm_admin over a user in the same org, or any site admin.
                'requirement' => function ($row) use ($me, $isSiteAdmin) {
                    return !empty($isSiteAdmin)
                        || (!empty($me['Role']['perm_admin'])
                            && isset($row['User']['org_id'])
                            && $row['User']['org_id'] == $me['org_id']);
                },
            ],
            [
                'type' => 'divider',
                'requirement' => !empty($isSiteAdmin),
            ],
            [
                'type' => 'modal',
                'label' => __('Destroy sessions'),
                'icon' => 'bomb',
                'class' => 'text-danger',
                'size' => 'sm',
                'url' => $baseurl . '/admin/users/destroy/%id%',
                'requirement' => !empty($isSiteAdmin),
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'size' => 'sm',
                'url' => $baseurl . '/admin/users/delete/%id%',
                'requirement' => !empty($isSiteAdmin),
            ],
        ],
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $users,
            'primary_id_path' => 'User.id',
            'row_dblclick_url' => $baseurl . '/admin/users/view/%id%',
            'filter_bar' => [
                'children' => [
                    [
                        'type' => 'search',
                        'mode' => 'event',
                        'name' => 'all',
                        'placeholder' => __('Search by email, org or role'),
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'name' => 'status',
                                'label' => __('Status'),
                                'options' => [
                                    ''         => __(''),
                                    'enabled'  => __('Enabled'),
                                    'disabled' => __('Disabled'),
                                    'inactive' => __('Inactive'),
                                ]
                            ]
                        ]
                    ],
                ],
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/admin/users',
]);
?>
