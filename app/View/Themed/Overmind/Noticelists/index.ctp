<?php
$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Noticelist.id',
        'state_path' => 'Noticelist.enabled',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/noticelists/view/%id%'
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'times-circle text-danger',
                'icon_off' => 'check-circle text-success',
                'url' => '/noticelists/%action%/%id%',
                'state_path' => 'Noticelist.enabled',
                'requirement' => $isSiteAdmin
            ]
        ]
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
];

if ($this->Acl->canAccess('noticelists', 'update')) {
    $this->set('headerActions', [
        [
            'type' => 'post',
            'label' => __('Update Noticelists'),
            'icon' => 'sync',
            'url' => $baseurl . '/noticelists/update'
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
                        'button' => __('Filter'),
                        'placeholder' => __('Not available for the moment'),
                        'searchKey' => 'quickFilter',
                    ]
                ],
                'enable' => 1
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/noticelists'
]);