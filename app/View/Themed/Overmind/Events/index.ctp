<?php

$orgOptions = array_merge(
    ['' => 'All'],
    array_combine($orgs = array_diff(array_unique(Hash::extract($events, '{n}.Orgc.name')), ['All']), $orgs)
);

$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Event.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/events/view/%id%'
            ],
            [
                'type' => 'link',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/events/edit/%id%'
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Unpublish'),
                'label_off' => __('Publish'),
                'icon_on' => 'download',
                'icon_off' => 'upload',
                'class_on' => 'text-danger',
                'class_off' => 'text-success',
                'url' => $baseurl . '/events/togglePublish/%id%',
                'onclick' => 'event.preventDefault(); publishPopup(%id%);',
                'state_path' => 'Event.published',
                //'requirement' => $this->Acl->canPublishEvent($event)
            ]
        ]
    ],
    [
        'name' => __('ID'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id',
        'element' => 'id',
        'card_section' => 'meta'
    ],
    // [
    //     'name' => __('Distribution'),
    //     'data_path' => 'Event.distribution',
    //     'element' => 'distribution',
    //     'display' => 'long'
    // ],
    [
        'name' => __('Info'),
        'data_path' => 'Event',
        'element' => 'info',
        'card_section' => 'title'
    ],
    [
        'name' => __('Published'),
        'sort' => 'Event.published',
        'data_path' => 'Event.published',
        'element' => 'enabled',
        'card_section' => 'meta',
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Orgc.name',
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'card_section' => 'title'
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'EventTag',
        'element' => 'tag',
        'card_section' => 'tag',
    ],
    [
        'name' => __('Galaxy'),
        'data_path' => 'GalaxyCluster',
        'element' => 'galaxy',
        'card_section' => 'galaxy',
    ],
    [
        'name' => __('Contents'),
        'data_path' => 'Event',
        'element' => 'event_contents',
        'card_section' => 'extra'
    ],
];

// if ($this->Acl->canAccess('noticelists', 'update')) {
//     $this->set('headerActions', [
//         [
//             'url' => $baseurl . '/noticelists/update',
//             'label' => __('Update Noticelists'),
//             'icon' => 'sync'
//         ]
//     ]);
// }

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $events,
            'top_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search events...'
                    ],
                    [
                        'type' => 'dropdown',
                        'label' => 'Distribution',
                        'name' => 'distribution',
                        'options' => [
                            '' => 'All',
                            '0' => 'Your organisation only',
                            '1' => 'Community',
                            '2' => 'Connected communities',
                            '3' => 'All communities'
                        ]
                    ],
                    [
                        'type' => 'dropdown',
                        'label' => 'Published',
                        'name' => 'published',
                        'options' => [
                            '' => 'All',
                            '1' => 'Published',
                            '0' => 'Not published'
                        ]
                    ],
                    [
                        'type' => 'dropdown',
                        'label' => 'Organisation',
                        'name' => 'org_id',
                        'options' => $orgOptions
                    ]
                ]
            ],
            'fields' => $fields,
        ]
    ]
]);
?>
