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
        'name' => __('ID'),
        'sort' => 'Regexp.id',
        'data_path' => 'Regexp.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Exportable'),
        'data_path' => 'Regexp.regexp',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Replacement'),
        'data_path' => 'Regexp.replacement',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => 'Regexp.type',
        'data_path' => 'Regexp.type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ]
];


$headerActions = [];
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
                        'placeholder' => 'Not available for the moment',
                        'name'        => 'value',
                        'mode'        => 'legacy',
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'label' => __('Type'),
                                'name' => 'type',
                                'options' => $typeOptions
                            ]
                        ]
                    ]
                ],
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/regexp'
]);

?>