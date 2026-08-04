<?php
// Header section
$headerTitle = __('Galaxy Cluster Blocklists');
$headerDescription = __('Galaxy clusters matching a blocklisted UUID are prevented from being created (also via synchronisation) on this instance.');

$headerActions = [];
if ($this->Acl->canAccess('galaxyClusterBlocklists', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add cluster blocklist'),
        'icon' => 'plus',
        'url' => $baseurl . '/galaxyClusterBlocklists/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('galaxyClusterBlocklists', 'edit');
$canDelete = $this->Acl->canAccess('galaxyClusterBlocklists', 'delete');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'GalaxyClusterBlocklist.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'GalaxyClusterBlocklist.id',
        'data_path' => 'GalaxyClusterBlocklist.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Cluster UUID'),
        'sort' => 'GalaxyClusterBlocklist.cluster_uuid',
        'data_path' => 'GalaxyClusterBlocklist.cluster_uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Creating organisation'),
        'sort' => 'GalaxyClusterBlocklist.cluster_orgc',
        'data_path' => 'GalaxyClusterBlocklist.cluster_orgc',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Cluster value'),
        'sort' => 'GalaxyClusterBlocklist.cluster_info',
        'data_path' => 'GalaxyClusterBlocklist.cluster_info',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Comment'),
        'sort' => 'GalaxyClusterBlocklist.comment',
        'data_path' => 'GalaxyClusterBlocklist.comment',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'GalaxyClusterBlocklist.created',
        'data_path' => 'GalaxyClusterBlocklist.created',
        'element' => 'datetime',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'GalaxyClusterBlocklist.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/galaxyClusterBlocklists/edit/%id%',
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/galaxyClusterBlocklists/deleteSelection/%id%',
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
    'item_url' => '/galaxyClusterBlocklists'
]);
?>
