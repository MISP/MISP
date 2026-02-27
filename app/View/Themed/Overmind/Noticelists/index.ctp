<?php
$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Noticelist.id',
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
                'url' => '/noticelists/toggleEnable/%id%',
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
        'card_section' => 'meta'
    ],
    [
        'name' => __('Name'),
        'sort' => 'Noticelist.name',
        'data_path' => 'Noticelist.name',
        'card_section' => 'title'
    ],
    [
        'name' => __('Expanded Name'),
        'sort' => 'Noticelist.expanded_name',
        'data_path' => 'Noticelist.expanded_name',
        'card_section' => 'title'
    ],
    [
        'name' => __('Ref'),
        'data_path' => 'Noticelist.ref',
        'element' => 'links',
        'card_section' => 'links'
    ],
    [
        'name' => __('Geographical area'),
        'data_path' => 'Noticelist.geographical_area',
        'element' => 'flag',
        'card_section' => 'extra'
    ],
    [
        'name' => __('Version'),
        'data_path' => 'Noticelist.version',
        'element' => 'version',
        'card_section' => 'meta'
    ],
    [
        'name' => __('Enabled'),
        'data_path' => 'Noticelist.enabled',
        'element' => 'enabled',
        'card_section' => 'meta',
        'requirement' => $isSiteAdmin,
    ],
    [
        'name' => __('Default'),
        'data_path' => 'Noticelist.enabled',
        'element' => 'boolean',
        'card_section' => 'meta',
        'colors' => true,
        'requirement' => !$isSiteAdmin,
    ],
];

if ($this->Acl->canAccess('noticelists', 'update')) {
    $this->set('headerActions', [
        [
            'url' => $baseurl . '/noticelists/update',
            'label' => __('Update Noticelists'),
            'icon' => 'sync'
        ]
    ]);
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'searchKey' => 'quickFilter',
                    ]
                ]
            ],
            'fields' => $fields,
        ]
    ]
]);