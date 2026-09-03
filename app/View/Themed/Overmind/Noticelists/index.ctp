<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('noticelists', 'update')) {
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Update Noticelists'),
        'icon' => 'sync',
        'url' => $baseurl . '/noticelists/update'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Noticelist.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Noticelist.id',
        'data_path' => 'Noticelist.id',
        'element' => 'id',
        'url' => $baseurl . '/noticelists/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Noticelist.name',
        'data_path' => 'Noticelist.name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Expanded Name'),
        'sort' => 'Noticelist.expanded_name',
        'data_path' => 'Noticelist.expanded_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Ref'),
        'data_path' => 'Noticelist.ref',
        'element' => 'links',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Geographical area'),
        'data_path' => 'Noticelist.geographical_area',
        'element' => 'country',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Version'),
        'data_path' => 'Noticelist.version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Enabled'),
        'data_path' => 'Noticelist.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'requirement' => $isSiteAdmin,
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Default'),
        'data_path' => 'Noticelist.enabled',
        'element' => 'default',
        'card_section' => 'top',
        'colors' => true,
        'requirement' => !$isSiteAdmin,
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Noticelist.id',
        'enable_path' => 'Noticelist.enabled',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/noticelists/view/%id%'
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'fas fa-stop text-danger',
                'icon_off' => 'fas fa-play text-success',
                'url' => '/noticelists/%action%/%id%',
                'enable_path' => 'Noticelist.enabled',
                'requirement' => $isSiteAdmin
            ]
        ]
    ]
];


echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxxxl' => 3],
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Not available for the moment'),
                        'searchKey' => 'quickFilter',
                    ]
                ],
                'enable' => 1
            ],
            'fields' => $fields,
            'primary_id_path' => 'Noticelist.id',
            'row_dblclick_url' => $baseurl . '/noticelists/view/%id%',
        ]
    ],
    'item_url' => '/noticelists'
]);