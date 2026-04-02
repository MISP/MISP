<?php
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
 * - state_path     : Path to the boolean value (toggle)
 */

$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Warninglist.id',
        'state_path' => 'Warninglist.enabled',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/warninglists/view/%id%'
            ],
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/warninglists/edit/%id%',
                'requirement' => 'check_edit_warninglists_rights'
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/warninglists/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => 'check_site_admin'
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => 'check_site_admin'
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'stop',
                'icon_off' => 'play',
                'url' => $baseurl . '/warninglists/toggleEnable/%id%', 
                'state_path' => 'Warninglist.enabled',
                'requirement' => 'check_site_admin'
            ]
        ]
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
        'data_path' => 'Warninglist',
        'element' => 'warninglist_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Version'),
        'data_path' => 'Warninglist.version',
        'element' => 'version',
        'card_section' => 'extra',
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
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ]
];


$headerActions = [];
if ($this->Acl->canAccess('warninglists', 'update')) {
    $headerActions[] = [
        'type' => 'post',
        'label' => __('Update Warninglists'),
        'icon' => 'sync',
        'url' => $baseurl . '/warninglists/update'
    ];
}

if ($this->Acl->canAccess('warninglists', 'add')) {
    $headerActions[] = [
        'type' => 'ajax',
        'label' => __('Add Warninglist'),
        'icon' => 'plus',
        'url' => $baseurl . '/warninglists/add'
    ];
}
$this->set('headerActions', $headerActions);

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
        ]
    ],
    'item_url' => '/warninglists'
]);

?>