<?php
// Header section
$headerTitle = __('UserLoginProfile Index');
$headerDescription = __('A list of confirmed authentication profiles bound to a user. This is used by the backend to identify suspicious connections from a user and raise alerts.');

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', []);

// $delete_buttons is set by the controller: true for (org/site) admins, who may
// remove a profile via the existing admin_delete postLink. Normal users get a
// read-only list of their own profiles.
$showDelete = !empty($delete_buttons);

$fields = [
    [
        'name' => '#',
        'sort' => 'UserLoginProfile.id',
        'data_path' => 'UserLoginProfile.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('User'),
        'sort' => 'User.email',
        'data_path' => 'User.email',
        'element' => 'user_link',
        'id_path' => 'User.id',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('IP'),
        'sort' => 'UserLoginProfile.ip',
        'data_path' => 'UserLoginProfile.ip',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('User-Agent'),
        'sort' => 'UserLoginProfile.user_agent',
        'data_path' => 'UserLoginProfile.user_agent',
        'card_section' => 'links',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Reported on'),
        'data_path' => 'UserLoginProfile.created_at',
        'element' => 'datetime',
        'empty' => __('Never'),
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Status'),
        'sort' => 'UserLoginProfile.status',
        'data_path' => 'UserLoginProfile.status',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Accept Language'),
        'sort' => 'UserLoginProfile.accept_lang',
        'data_path' => 'UserLoginProfile.accept_lang',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('GeoIP'),
        'sort' => 'UserLoginProfile.geoip',
        'data_path' => 'UserLoginProfile.geoip',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('UA.pattern'),
        'sort' => 'UserLoginProfile.ua_pattern',
        'data_path' => 'UserLoginProfile.ua_pattern',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('UA.Platform'),
        'sort' => 'UserLoginProfile.ua_platform',
        'data_path' => 'UserLoginProfile.ua_platform',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('UA.Browser'),
        'sort' => 'UserLoginProfile.ua_browser',
        'data_path' => 'UserLoginProfile.ua_browser',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
    ],
];

if ($showDelete) {
    $fields[] = [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'UserLoginProfile.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'postLink',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/admin/UserLoginProfiles/delete/%id%',
                'class' => 'text-danger',
                'confirm' => __('Are you sure you want to delete this profile?'),
            ],
        ],
    ];
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'mode' => 'quickFilter',
                    ],
                ],
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/userLoginProfiles'
]);
