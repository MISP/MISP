<?php
// Temporary fix to avoid errors as these variables are defined in AttributesController
$categoryOptions = isset($categoryOptions) ? $categoryOptions : null;
$typeOptions = isset($typeOptions) ? $typeOptions : null;
$orgOptions = isset($orgOptions) ? $orgOptions : null;
$tagOptions = isset($tagOptions) ? $tagOptions : null;
$galaxyOptions = isset($galaxyOptions) ? $galaxyOptions : null;

/**
 * ==============================================================
 * Definition of fields displayed in the scaffold
 * ==============================================================
 *
 * Possible fields for each entry:
 *
 * - name           : Label displayed in the table
 * - sort           : Database field used for sorting
 * - data_path      : Path to the data in the $events array
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


$model = (isset($attributes[0]) && isset($attributes[0]['Attribute'])) ? 'Attribute' : null;

$path = function($field) use ($model) {
    if (empty($model)) {
        return $field;
    }
    if (empty($field)) {
        return $model;
    }
    return $model . '.' . $field;
};

$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Attribute.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/attributes/edit/%id%',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'ajax',
                'label' => __('Soft Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/attributes/delete/%id%',
                'class' => 'text-warning',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/attributes/delete/%id%/true',
                'class' => 'text-danger',
                'requirement' => 'check_edit_rights'
            ]
        ]
    ]
];

if (!empty($show_event_id)) {
    $fields[] = [
        'name' => __('Event ID'),
        'sort' => $path('event_id'),
        'data_path' => 'Event.id',
        'element' => 'id',
        'url' => $baseurl . '/events/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ];
}

$fields = array_merge($fields, [
    [
        'name' => __('Distribution'),
        'data_path' => $path('distribution'),
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Value'),
        'data_path' => $path(''),
        'element' => 'value',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Category'),
        'sort' => $path('category'),
        'data_path' => $path('category'),
        'element' => 'category',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => $path('type'),
        'data_path' => $path('type'),
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
]);

if (!empty($show_event_id)) {
    $fields = array_merge($fields, [
    [
        'name' => __('Creator Org'),
        'sort' => 'Event.Orgc.name',
        'data_path' => 'Event.Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Event.Org.name',
        'data_path' => 'Event.Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card']
    ]
    ]);
}

$fields = array_merge($fields, [
    [
        'name' => __('Tags'),
        'data_path' => $path('AttributeTag'),
        'element' => 'tag',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Galaxy'),
        'data_path' => $path('Galaxy'),
        'element' => 'galaxy',
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card']
    ],

    [
        'name' => __('Sightings'),
        'data_path' => $path(''),
        'element' => 'sightings',
        'card_section' => 'extra',
        'display_in' => ['card']
    ],
    // [
    //     'name' => __('Created'),
    //     'data_path' => $path('date'),
    //     'element' => 'timestamp',
    //     'mode' => 'created',
    //     'card_section' => 'meta',
    //     'display_in' => ['card']
    // ],
    [
        'name' => __('Last Modified'),
        'data_path' => $path('timestamp'),
        'element' => 'timestamp',
        'mode' => 'modified',
        'card_section' => 'top',
        'display_in' => ['card']
    ]
]);



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
 * - item_url                     : Base URL for pagination / filters
 */

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $attributes,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        "placeholder" => "Filters aren't implemented for the moment"
                    ],
                    [
                        'type' => 'button',
                        'label' => __('My attributes'),
                        'icon' => 'user',
                        'class' => 'btn btn-primary',
                        'url' => $baseurl . '/attributes/index/searchemail:' . urlencode($me['email'])
                    ],
                    [
                        'type' => 'button',
                        'label' => __('Org attributes'),
                        'icon' => 'building',
                        'class' => 'btn btn-primary',
                        'url' => $baseurl . '/attributes/index/searchorg:' . urlencode($me['org_id'])
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
                                'label' => __('Creator Org'),
                                'name' => 'org',
                                'options' => $orgOptions
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Tags'),
                                'name' => 'tag',
                                'options' => $tagOptions
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Galaxy'),
                                'name' => 'galaxy',
                                'options' => $galaxyOptions
                            ]
                        ]
                    ]
                ],
                'delete' => '/delete',
                'mass_edit' => 1,
                'mass_tag' => 1,
                'mass_local_tag' => 1,
                'mass_cluster' => 1,
                'mass_local_cluster' => 1,
                'mass_object' => 1,
                'mass_relationship' =>1,
                'mass_sighting' =>1,
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/attributes'
]);

?>