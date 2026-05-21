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


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Collection.id',
        'card_section' => 'selector',
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
        'data_path' => 'Collection',
        'element' => 'collection_name',
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
        'name' => __('Elements'),
        'sort' => 'Collection.element_count',
        'data_path' => 'Collection.element_count',
        'element' => 'count',
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
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/collections/view/%id%'
            ],
            [
                'type' => 'link',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/collections/edit/%id%',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'ajax',
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
                        'placeholder' => __('Search by collection name'),
                        'name'          => 'quickFilter',
                        'mode'      => 'quickFilter',
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

?>