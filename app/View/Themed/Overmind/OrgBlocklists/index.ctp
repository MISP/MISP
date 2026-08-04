<?php
// Header section
$headerTitle = __('Organisation Blocklists');
$headerDescription = __('Blocklisting an organisation prevents the creation and synchronisation of any of its events on this instance.');

$headerActions = [];
if ($this->Acl->canAccess('orgBlocklists', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add org blocklist'),
        'icon' => 'plus',
        'url' => $baseurl . '/orgBlocklists/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('orgBlocklists', 'edit');
$canDelete = $this->Acl->canAccess('orgBlocklists', 'delete');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'OrgBlocklist.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'OrgBlocklist.id',
        'data_path' => 'OrgBlocklist.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Organisation UUID'),
        'sort' => 'OrgBlocklist.org_uuid',
        'data_path' => 'OrgBlocklist.org_uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Organisation name'),
        'sort' => 'OrgBlocklist.org_name',
        'data_path' => 'OrgBlocklist.org_name, OrgBlocklist.comment',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Blocked amount'),
        'sort' => 'OrgBlocklist.blocked_data.blocked_amount',
        'data_path' => 'OrgBlocklist.blocked_data.blocked_amount',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Blocked last time'),
        'sort' => 'OrgBlocklist.blocked_data.blocked_last_time',
        'data_path' => 'OrgBlocklist.blocked_data.blocked_last_time',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'OrgBlocklist.created',
        'data_path' => 'OrgBlocklist.created',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'OrgBlocklist.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/orgBlocklists/edit/%id%',
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/orgBlocklists/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ]))
    ]
];

// OrgBlocklistsController::index() does not build search params (parity with
// the legacy index, which had no search box), so we omit the search child and
// keep the filter bar only for the view toggle + bulk-delete toolbar.
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
            'data' => $response,
            'filter_bar' => $filterBar,
            'fields' => $fields,
        ]
    ],
    'item_url' => '/orgBlocklists'
]);
?>
