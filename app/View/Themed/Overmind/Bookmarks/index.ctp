<?php
// Header section
$headerTitle = __('Bookmarks');
$headerDescription = __('Create bookmarks that appear in the navigation top bar. Each bookmark can be exposed to all users belonging to its organisation.');

$headerActions = [];
if ($this->Acl->canAccess('bookmarks', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add bookmark'),
        'icon' => 'plus',
        'url' => $baseurl . '/bookmarks/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

// Per-row ownership: a user may modify/delete a bookmark that is theirs, or
// (as an org admin) one belonging to their org, or as site admin. Mirrors
// Bookmark::mayModify and the legacy index row-action requirements.
$mayModifyRow = function ($row) use ($me) {
    return !empty($me['Role']['perm_site_admin'])
        || $me['id'] == $row['Bookmark']['user_id']
        || (!empty($me['Role']['perm_admin']) && $me['org_id'] == $row['Bookmark']['org_id']);
};

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Bookmark.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Bookmark.id',
        'data_path' => 'Bookmark.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Bookmark.org_id',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('User'),
        'sort' => 'User.email',
        'data_path' => 'User.email',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Bookmark.name',
        'data_path' => 'Bookmark.name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('URL'),
        'sort' => 'Bookmark.url',
        'data_path' => 'Bookmark.url',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Comment'),
        'sort' => 'Bookmark.comment',
        'data_path' => 'Bookmark.comment',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Exposed to Org'),
        'title' => __('Is this bookmark exposed to all users belonging to the bookmark\'s organisation'),
        'sort' => 'Bookmark.exposed_to_org',
        'data_path' => 'Bookmark.exposed_to_org',
        'element' => 'flag',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Bookmark.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/bookmarks/view/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/bookmarks/edit/%id%',
                'requirement' => $mayModifyRow,
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/bookmarks/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $mayModifyRow,
            ],
        ]
    ]
];

$filterBar = [
    'pull' => 'right',
    'children' => [
        [
            'type' => 'button',
            'label' => __('All bookmarks'),
            'url' => $baseurl . '/bookmarks/index',
            'class' => 'btn btn-sm ' . ($scope === 'all' ? 'btn-primary' : 'btn-outline-primary'),
        ],
        [
            'type' => 'button',
            'label' => __('My bookmarks'),
            'url' => $baseurl . '/bookmarks/index/scope:mine',
            'class' => 'btn btn-sm ' . ($scope === 'mine' ? 'btn-primary' : 'btn-outline-primary'),
        ],
        [
            'type' => 'search',
            'button' => __('Search'),
            'placeholder' => __('Search by name or URL'),
            'mode' => 'quickFilter',
        ],
    ],
    'delete' => '/deleteSelection',
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => $filterBar,
            'fields' => $fields,
        ]
    ],
    'item_url' => '/bookmarks'
]);
?>
