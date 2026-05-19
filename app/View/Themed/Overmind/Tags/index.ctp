<?php
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Tag.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Tag.id',
        'data_path' => 'Tag.id',
        'element' => 'id',
        'url' => $baseurl . '/tags/viewGraph/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Tag.name',
        'data_path' => 'Tag',
        'element' => 'tag_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Local only'),
        'sort' => 'Tag.local_only',
        'data_path' => 'Tag.local_only',
        'element' => 'local',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Hidden'),
        'sort' => 'Tag.hide_tag',
        'data_path' => 'Tag.hide_tag',
        'element' => 'hide',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Exportable'),
        'sort' => 'Tag.exportable',
        'data_path' => 'Tag.exportable',
        'element' => 'exportable',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Relations'),
        'data_path' => 'Tag',
        'element' => 'tag_relations',
        'card_section' => 'meta',
        'display_in' => ['table','card']
    ],
    [
        'name' => __('Restrictions'),
        'data_path' => '',
        'element' => 'tag_restriction',
        'card_section' => 'meta',
        'display_in' => ['table','card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Tag.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View graph'),
                'icon' => 'eye',
                'url' => $baseurl . '/tags/viewGraph/%id%'
            ],
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/tags/edit/%id%',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/tags/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => 'check_edit_rights'
            ]
        ]
    ]
];

/**
 * Header actions (optionnel)
 */
if ($this->Acl->canAccess('tags', 'add')) {
    $this->set('headerActions', [
        [
            'type' => 'ajax',
            'label' => __('Add Tag'),
            'url' => $baseurl . '/tags/add',
            'icon' => 'plus'
        ]
    ]);
}

/**
 * Scaffold
 */
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by tag name'),
                        'name'          => 'searchall',
                        'mode'      => 'legacy',
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'label' => __('Favourite'),
                                'name' => 'favouritesOnly',
                                'options' => [
                                    '' => '',
                                    '1' => 'Favourite only',
                                    '0' => 'Not favourite'
                                ]
                            ],
                        ]
                    ]
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
            'primary_id_path' => 'Tag.id',
            'row_dblclick_url' => $baseurl . '/tags/viewGraph/%id%',
        ]
    ],
    'item_url' => '/tags'
]);

?>