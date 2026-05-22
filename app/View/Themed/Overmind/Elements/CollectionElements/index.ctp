<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


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
        'name' => __('UUID'),
        'sort' => 'uuid',
        'data_path' => 'uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => 'type',
        'data_path' => 'element_type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Element'),
        'data_path' => '',
        'element' => 'collection_element',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'data_path' => 'id',
        'element' => 'row_actions',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/collectionElements/deleteSelection/%id%',
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
                    // Has to be implemented in the controller first
                    // [
                    //     'type' => 'search',
                    //     'button' => __('Search'),
                    //     'placeholder' => __('Search by element name'),
                    //     'name'          => 'quickFilter',
                    //     'mode'      => 'quickFilter',
                    // ]
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/collectionElements'
]);

?>