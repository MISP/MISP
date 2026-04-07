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
        'data_path' => 'Allowedlist.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/admin/allowedlists/edit/%id%',
                'requirement' => 'check_site_admin'
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/admin/allowedlists/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => 'check_site_admin'
            ]
        ]
    ],
    [
        'name' => __('ID'),
        'sort' => 'Allowedlist.id',
        'data_path' => 'Allowedlist.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'data_path' => 'Allowedlist.name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ]
];



if ($this->Acl->canAccess('allowedlists', 'admin_add')) {
    $headerActions[] = [
        'type' => 'ajax',
        'label' => __('Add Allowedlist'),
        'icon' => 'plus',
        'url' => $baseurl . '/admin/allowedlists/add'
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
            'data' => $list,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search by allowedlist name',
                        'name'        => 'value',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/admin/allowedlists'
]);

?>