<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];

if ($this->Acl->canAccess('correlation_exclusions', 'clean')) {
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Clean up correlations'),
        'icon' => 'sync',
        'url' => $baseurl . '/correlation_exclusions/clean'
    ];
}

if ($this->Acl->canAccess('correlation_exclusions', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add correlation exclusion entry'),
        'icon' => 'plus',
        'url' => $baseurl . '/correlation_exclusions/add'
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
 * - state_path     : Path to the boolean value (toggle)
 */

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'CorrelationExclusion.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'CorrelationExclusion.id',
        'data_path' => 'CorrelationExclusion.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Value'),
        'data_path' => 'CorrelationExclusion.value',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Comment'),
        'data_path' => 'CorrelationExclusion.comment',
        'element' => '',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('JSON source'),
        'sort' => 'CorrelationExclusion.from_json',
        'data_path' => 'CorrelationExclusion.from_json',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'CorrelationExclusion.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/correlation_exclusions/edit/%id%',
                'requirement' => 'check_site_admin'
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/correlation_exclusions/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => 'check_site_admin'
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
            'data' => $data,
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxxxl' => 3],
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search by exclusion value',
                        'name'        => 'value',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/correlation_exclusions'
]);

?>