<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <p class="mb-0 text-secondary-emphasis">
                <?= __('You can find a list of communities below that chose to advertise their existence to the general MISP user-base. Requesting access to any of those communities is of course no guarantee of being permitted access, it is only meant to simplify the means of finding the various communities that one may be eligible for. Get in touch with the MISP project maintainers if you would like your community to be included in the list.') ?>
            </p>
        </div>
    </div>
</div>

<?php
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
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/SharingGroupBlueprints/view/%id%',
            ],
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/SharingGroupBlueprints/edit/%id%',
                'requirement' => $me['Role']['perm_sharing_group']
            ],
            [
                'type' => 'ajax',
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
                'type' => 'ajax',
                'label' => __('(Re)generate sharing group based on blueprint'),
                'icon' => 'recycle',
                'url' => $baseurl . '/SharingGroupBlueprints/execute/%id%',
                'requirement' => $me['Role']['perm_sharing_group']
            ],
            [
                'type' => 'ajax',
                'label' => __("Encode blueprint's contents as a sync rule"),
                'icon' => 'filter',
                'url' => $baseurl . '/SharingGroupBlueprints/encodeSyncRule/%id%',
                'requirement' => $me['Role']['perm_sharing_group']
            ]
        ]
    ]
];

if ($this->Acl->canAccess('SharingGroupBlueprints', 'add')) {
    $this->set('headerActions', [
        [
            'type' => 'ajax',
            'label' => __('Add SharingGroupBlueprint'),
            'icon' => 'plus',
            'url' => $baseurl . '/SharingGroupBlueprints/add'
        ]
    ]);
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
