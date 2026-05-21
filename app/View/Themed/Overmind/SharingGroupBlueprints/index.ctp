<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('Sharing Group Blueprints are blueprints for the creation of sharing groups');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('SharingGroupBlueprints', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add SharingGroupBlueprint'),
        'icon' => 'plus',
        'url' => $baseurl . '/SharingGroupBlueprints/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'SharingGroupBlueprint.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'SharingGroupBlueprint.id',
        'data_path' => 'SharingGroupBlueprint.id',
        'element' => 'id',
        'url' => $baseurl . '/SharingGroupBlueprints/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'SharingGroupBlueprint.name',
        'data_path' => 'SharingGroupBlueprint.name, ',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner'),
        'sort' => 'Organisation.name',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('SharingGroup'),
        'sort' => 'SharingGroupBlueprint.sharing_group_id',
        'data_path' => 'SharingGroupBlueprint.sharing_group_id',
        'element' => 'blueprint_sharing_group',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Rules'),
        'data_path' => 'SharingGroupBlueprint.rules',
        'element' => 'json',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'SharingGroupBlueprint.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/SharingGroupBlueprints/view/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/SharingGroupBlueprints/edit/%id%',
                'requirement' => $me['Role']['perm_sharing_group']
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/SharingGroupBlueprints/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_sharing_group']
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $me['Role']['perm_sharing_group']
            ],
            [
                'type' => 'modal',
                'label' => __('(Re)generate sharing group based on blueprint'),
                'icon' => 'recycle',
                'url' => $baseurl . '/SharingGroupBlueprints/execute/%id%',
                'requirement' => $me['Role']['perm_sharing_group']
            ],
            [
                'type' => 'modal',
                'label' => __("Encode blueprint's contents as a sync rule"),
                'icon' => 'filter',
                'url' => $baseurl . '/SharingGroupBlueprints/encodeSyncRule/%id%',
                'requirement' => $me['Role']['perm_sharing_group']
            ]
        ]
    ]
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search in all fields',
                        'name'        => '',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection',
            ],
            'fields' => $fields,
            'primary_id_path' => 'SharingGroupBlueprint.id',
            'row_dblclick_url' => $baseurl . '/SharingGroupBlueprints/view/%id%',
        ]
    ],
    'item_url' => '/SharingGroupBlueprints'
]);
