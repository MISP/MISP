<?php
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name, description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Version'),
        'data_path' => 'version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Highlighted'),
        'sort' => 'highlighted',
        'data_path' => 'highlighted',
        'element' => 'highlighted',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Formats'),
        'data_path' => 'format',
        'element' => 'format_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Usage'),
        'sort' => 'usage_all',
        'data_path' => 'usage',
        'element' => 'relationship_usage',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'id',
        'highlight_path' => 'highlighted',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/object_relationships/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/object_relationships/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Remove Highlight'),
                'label_off' => __('Highlight'),
                'icon_on' => 'down-long text-primary',
                'icon_off' => 'highlighter text-primary',
                'url' => '/object_relationships/%action%/%name%',
                'url_params_data_paths' => ['name' => 'name'],
                'highlight_path' => 'highlighted',
                'requirement' => $isSiteAdmin
            ]
        ]
    ]
];

if ($this->Acl->canAccess('object_relationships', 'add')) {
    $this->set('headerActions', [
        [
            'type' => 'ajax',
            'label' => __('Add Object Relationship'),
            'icon' => 'plus',
            'url' => $baseurl . '/object_relationships/add'
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
                        'placeholder' => 'Search by relationship name',
                        'name'        => 'name',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection',
                'highlight' => 1,
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/object_relationships'
]);
?>