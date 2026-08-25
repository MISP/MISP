<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('warninglists', 'update')) {
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Update Warninglists'),
        'icon' => 'sync',
        'url' => $baseurl . '/warninglists/update'
    ];
}

if ($this->Acl->canAccess('warninglists', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Warninglist'),
        'icon' => 'plus',
        'url' => $baseurl . '/warninglists/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);



/**
 * ==============================================================
 * Definition of fields displayed in the scaffold
 * ==============================================================
 *
 * Possible fields for each entry:
 *
 * - name           : Label displayed in the table
 * - sort           : Database field used for sorting
 * - data_path      : Path to the data in the $warninglists array
 * - element        : Template used for rendering
 * - url            : Associated link (supports %id%)
 * - card_section   : Display section in card mode
 * - display_in     : ['table', 'card']
 * - mode           : Specific option for certain elements (ex: timestamp)
 * - actions        : Available actions (for element = selector)
 *
 * Fields specific to actions:
 *
 * - type           : link | ajax | toggle | divider
 * - label          : Displayed text
 * - label_on/off   : Text for toggle
 * - icon           : FontAwesome icon
 * - icon_on/off    : Toggle icon
 * - url            : URL (supports %id% and %action%)
 * - class          : CSS class
 * - requirement    : Permission check function
 * - enable_path     : Path to the enable value (toggle)
 */

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Warninglist.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Warninglist.id',
        'data_path' => 'Warninglist.id',
        'element' => 'id',
        'url' => $baseurl . '/warninglists/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Warninglist.name',
        'data_path' => 'Warninglist.name, Warninglist.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Version'),
        'data_path' => 'Warninglist.version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Category'),
        'sort' => 'Warninglist.category',
        'data_path' => 'Warninglist.category',
        'element' => 'category',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => 'Warninglist.type',
        'data_path' => 'Warninglist.type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Default'),
        'sort' => 'Warninglist.default',
        'data_path' => 'Warninglist.default',
        'element' => 'default',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'Warninglist.enabled',
        'data_path' => 'Warninglist.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Entries'),
        'data_path' => 'Warninglist.warninglist_entry_count',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Warninglist.id',
        'enable_path' => 'Warninglist.enabled',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/warninglists/view/%id%'
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/warninglists/edit/%id%',
                'requirement' => function ($row) use ($me) {
                    return $me['Role']['perm_warninglist'] && !$row['Warninglist']['default'];
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/warninglists/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_warninglist']
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $me['Role']['perm_warninglist']
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'stop',
                'icon_off' => 'play',
                'url' => $baseurl . '/warninglists/toggleEnable/%id%', 
                'enable_path' => 'Warninglist.enabled',
                'requirement' => $me['Role']['perm_warninglist']
            ]
        ]
    ]
];


/**
 * ==============================================================
 * Call the generic scaffold
 * ==============================================================
 *
 * Main parameters:
 *
 * - scaffold_data.data.data       : Main dataset
 * - scaffold_data.data.filter_bar    : Filter bar configuration
 * - scaffold_data.data.fields     : Column definitions
 * - index_url                     : Base URL for pagination / filters
 */

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $warninglists,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search by warninglist name',
                        'name'        => 'value',
                        'mode'        => 'legacy',
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'label' => __('Category'),
                                'name' => 'category',
                                'options' => $categoryOptions
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Type'),
                                'name' => 'type',
                                'options' => $typeOptions
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Default'),
                                'name' => 'default',
                                'options' => [
                                    '' => '',
                                    '1' => 'Default',
                                    '0' => 'Not default'
                                ]
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Enabled'),
                                'name' => 'enabled',
                                'options' => [
                                    '' => '',
                                    '1' => 'Enabled',
                                    '0' => 'Not enabled'
                                ]
                            ]
                        ]
                    ]
                ],
                'enable' => 1,
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
            'primary_id_path' => 'Warninglist.id',
            'row_dblclick_url' => $baseurl . '/warninglists/view/%id%',
        ]
    ],
    'item_url' => '/warninglists'
]);

?>