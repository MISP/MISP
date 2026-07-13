<?php
// Header section
$headerTitle = __('Analyst Data Blocklists');
$headerDescription = __('Analyst data matching a blocklisted UUID is prevented from being created (also via synchronisation) on this instance.');

$headerActions = [];
if ($this->Acl->canAccess('analystDataBlocklists', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add analyst data blocklist'),
        'icon' => 'plus',
        'url' => $baseurl . '/analyst_data_blocklists/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('analystDataBlocklists', 'edit');
$canDelete = $this->Acl->canAccess('analystDataBlocklists', 'delete');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'AnalystDataBlocklist.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'AnalystDataBlocklist.id',
        'data_path' => 'AnalystDataBlocklist.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Analyst Data UUID'),
        'sort' => 'AnalystDataBlocklist.analyst_data_uuid',
        'data_path' => 'AnalystDataBlocklist.analyst_data_uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Creating organisation'),
        'sort' => 'AnalystDataBlocklist.analyst_data_orgc',
        'data_path' => 'AnalystDataBlocklist.analyst_data_orgc',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Analyst Data value'),
        'sort' => 'AnalystDataBlocklist.analyst_data_info',
        'data_path' => 'AnalystDataBlocklist.analyst_data_info',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Comment'),
        'sort' => 'AnalystDataBlocklist.comment',
        'data_path' => 'AnalystDataBlocklist.comment',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'AnalystDataBlocklist.created',
        'data_path' => 'AnalystDataBlocklist.created',
        'element' => 'datetime',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'AnalystDataBlocklist.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/analyst_data_blocklists/edit/%id%',
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/analyst_data_blocklists/deleteSelection/%id%',
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
            'placeholder' => __('Search by UUID, org, value or comment'),
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
        ]
    ],
    'item_url' => '/analyst_data_blocklists'
]);
?>
