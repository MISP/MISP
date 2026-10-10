<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('tagCollections', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Tag Collections'),
        'url' => $baseurl . '/tagCollections/addWithTags',
        'icon' => 'plus'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'TagCollection.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'TagCollection.id',
        'data_path' => 'TagCollection.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'TagCollection.uuid',
        'data_path' => 'TagCollection.uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'TagCollection.name',
        'data_path' => 'TagCollection.name, TagCollection.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('All orgs'),
        'sort' => 'TagCollection.all_orgs',
        'data_path' => 'TagCollection.all_orgs',
        'element' => 'all_orgs',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Creator Org'),
        'sort' => 'Organisation.name',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Creator User'),
        'sort' => 'User.email',
        'data_path' => 'User.email',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'TagCollectionTag',
        'element' => 'tag_list',
        'card_section' => 'tag',
        'display_in' => ['table','card']
    ],
    [
        'name' => __('Galaxies'),
        'data_path' => 'Galaxy',
        'element' => 'galaxy',
        'card_section' => 'galaxy',
        'display_in' => ['table','card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'TagCollection.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('Download configuration'),
                'icon' => 'cloud-arrow-down',
                'url' => $baseurl . '/tagCollections/view/%id%.json',
                'download' => true
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/tagCollections/editWithTags/%id%',
                'requirement' => $me['Role']['perm_tag_editor']
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/tagCollections/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_tag_editor']
            ]
        ]
    ]
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $list,
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxxxl' => 3],
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by tag collection name'),
                        'name'          => 'quickFilter',
                        'mode'      => 'quickFilter',
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
        ]
    ],
    'item_url' => '/tagCollections'
]);

?>