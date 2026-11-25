<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('collections', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Collection'),
        'url' => $baseurl . '/collections/add',
        'icon' => 'plus'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


// The collection types, as offered by the add/edit form, turned into filter
// options. The bar posts the bare key `type:` — CRUD qualifies it back to
// Collection.type.
$typeOptions = ['' => __('All')];
foreach (($dropdownData['types'] ?? []) as $value => $label) {
    $typeOptions[$value] = ucfirst(str_replace('_', ' ', (string)$label));
}

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Collection.id',
        'card_section' => 'selector',
    ],
    [
        'element' => 'collection_state',
        'header_html' => '<span class="te-hicon"><i class="fas fa-upload"></i></span>',
        'header_title' => __('Publish state'),
        'class' => 'ci-c-state',
        'header_class' => 'ci-c-state',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('ID'),
        'sort' => 'Collection.id',
        'data_path' => 'Collection.id',
        'element' => 'id',
        'url' => $baseurl . '/collections/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Collection.name',
        'data_path' => 'Collection.name, Collection.description',
        'distribution_path' => 'Collection.distribution',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
        [
        'name' => __('Type'),
        'data_path' => 'Collection.type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Orgc.name',
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Distribution'),
        'sort' => 'Collection.distribution',
        'data_path' => 'Collection.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Members'),
        'data_path' => 'Collection.element_count',
        'element' => 'collection_count',
        'count' => 'members',
        'class' => 'te-num',
        'header_class' => 'te-num',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Graphs'),
        'header_title' => __('Saved graphs'),
        'data_path' => 'Collection.graph_count',
        'element' => 'collection_count',
        'count' => 'graphs',
        'class' => 'te-num',
        'header_class' => 'te-num',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'Collection.created',
        'data_path' => 'Collection.created',
        'element' => 'timestamp',
        'mode' => 'created',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Modified'),
        'sort' => 'Collection.modified',
        'data_path' => 'Collection.modified',
        'element' => 'timestamp',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Collection.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/collections/view/%id%'
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/collections/edit/%id%',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/collections/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => 'check_edit_rights'
            ]
        ]
    ],

];

/**
 * Scaffold
 */
echo $this->element('genericElements/assetLoader', [
    'css' => ['events-index-table', 'collections-index'],
]);
echo '<div class="ci-index">';
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'cards_per_row' => ['' => 1, 'lg' => 2],
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by collection name'),
                        'name'          => 'quickFilter',
                        'mode'      => 'quickFilter',
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'label' => __('Type'),
                                'name' => 'type',
                                'options' => $typeOptions,
                            ],
                        ]
                    ],
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
            'primary_id_path' => 'Collection.id',
            'row_dblclick_url' => $baseurl . '/collections/view/%id%',
        ]
    ],
    'item_url' => '/collections'
]);
echo '</div>';

?>