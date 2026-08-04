<?php
// Header section
$headerTitle = __('Sighting Blocklists');
$headerDescription = __('Blocklisting an organisation prevents the creation of any sighting by that organisation on this instance, as well as the syncing of that organisation\'s sightings to this instance.');

$headerActions = [];
if ($this->Acl->canAccess('sightingBlocklists', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add sighting blocklist'),
        'icon' => 'plus',
        'url' => $baseurl . '/sightingBlocklists/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('sightingBlocklists', 'edit');
$canDelete = $this->Acl->canAccess('sightingBlocklists', 'delete');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'SightingBlocklist.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'SightingBlocklist.id',
        'data_path' => 'SightingBlocklist.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Organisation UUID'),
        'sort' => 'SightingBlocklist.org_uuid',
        'data_path' => 'SightingBlocklist.org_uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Organisation name'),
        'sort' => 'SightingBlocklist.org_name',
        'data_path' => 'SightingBlocklist.org_name, SightingBlocklist.comment',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Blocked amount'),
        'sort' => 'SightingBlocklist.blocked_data.blocked_amount',
        'data_path' => 'SightingBlocklist.blocked_data.blocked_amount',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Blocked last time'),
        'sort' => 'SightingBlocklist.blocked_data.blocked_last_time',
        'data_path' => 'SightingBlocklist.blocked_data.blocked_last_time',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'SightingBlocklist.created',
        'data_path' => 'SightingBlocklist.created',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'SightingBlocklist.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/sightingBlocklists/edit/%id%',
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/sightingBlocklists/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ]))
    ]
];

// SightingBlocklistsController::index() does not build search params (parity
// with the legacy index, which had no search box), so we omit the search child
// and keep the filter bar only for the view toggle + bulk-delete toolbar.
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
    'item_url' => '/sightingBlocklists'
]);
?>
