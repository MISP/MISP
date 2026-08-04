<?php
// Header section
$headerTitle = __('News');
$headerDescription = __('Announcements shown to users on the News page. New items are highlighted until read.');

$headerActions = [];
if ($this->Acl->canAccess('news', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add news item'),
        'icon' => 'plus',
        'url' => $baseurl . '/news/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('news', 'edit');
$canDelete = $this->Acl->canAccess('news', 'delete');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'News.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'News.id',
        'data_path' => 'News.id',
        'element' => 'id',
        'url' => '#',
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
        'name' => __('Title'),
        'sort' => 'News.title',
        'data_path' => 'News.title',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Message'),
        'data_path' => 'News.message',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created at'),
        'sort' => 'News.date_created',
        'data_path' => 'News.date_created',
        'element' => 'datetime',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'News.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/news/edit/%id%',
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/news/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ]))
    ]
];

// NewsController::admin_index() paginates directly and does not build search
// params (parity with the legacy admin index, which had no search box), so we
// omit the search child and keep the filter bar only for the view toggle +
// bulk-delete toolbar.
$filterBar = [
    'pull' => 'right',
    'children' => [],
];
if ($canDelete) {
    $filterBar['delete'] = '/deleteSelection';
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $newsItems,
            'filter_bar' => $filterBar,
            'fields' => $fields,
        ]
    ],
    'item_url' => '/news'
]);
?>
