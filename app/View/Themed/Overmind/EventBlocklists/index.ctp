<?php
// Header section
$headerTitle = __('Event Blocklists');
$headerDescription = __('Events matching a blocklisted UUID are prevented from being created (also via synchronisation) on this instance.');

$headerActions = [];
if ($this->Acl->canAccess('eventBlocklists', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add event blocklist'),
        'icon' => 'plus',
        'url' => $baseurl . '/eventBlocklists/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('eventBlocklists', 'edit');
$canDelete = $this->Acl->canAccess('eventBlocklists', 'delete');

// Card anatomy mirrors the Events index: an identity row (top), a bold
// title, then a `meta` footer separated by an <hr> holding the
// self-labelled metadata, with the actions in `extra`.
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'EventBlocklist.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'EventBlocklist.id',
        'data_path' => 'EventBlocklist.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Event UUID'),
        'sort' => 'EventBlocklist.event_uuid',
        'data_path' => 'EventBlocklist.event_uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Event info'),
        'sort' => 'EventBlocklist.event_info',
        'data_path' => 'EventBlocklist.event_info, EventBlocklist.comment',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Creating organisation'),
        'sort' => 'EventBlocklist.event_orgc',
        'data_path' => 'EventBlocklist.event_orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'EventBlocklist.created',
        'data_path' => 'EventBlocklist.created',
        'element' => 'timestamp',
        'mode' => 'created',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'EventBlocklist.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => array_values(array_filter([
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/eventBlocklists/edit/%id%',
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/eventBlocklists/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ]))
    ]
];

$filterBar = [
    'pull' => 'right',
    'children' => [
        [
            'type' => 'search',
            'button' => __('Search'),
            'placeholder' => __('Search by UUID, org, info or comment'),
            'name'        => 'searchall',
            'mode'        => 'legacy',
        ],
    ],
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
            'primary_id_path' => 'EventBlocklist.id',
        ]
    ],
    'item_url' => '/eventBlocklists'
]);
?>
