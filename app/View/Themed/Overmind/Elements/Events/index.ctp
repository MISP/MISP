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
 * - publish_path     : Path to the published value (toggle)
 */

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Event.id',
        'publish_path' => 'Event.published',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id',
        'element' => 'id',
        'url' => $baseurl . '/events/view2/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'Event.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Info'),
        'data_path' => 'Event',
        'element' => 'event_info',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Published'),
        'sort' => 'Event.published',
        'data_path' => 'Event.published',
        'element' => 'published',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Creator Org'),
        'sort' => 'Orgc.name',
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Org.name',
        'data_path' => 'Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'EventTag',
        'element' => 'tag_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Galaxy'),
        'data_path' => 'GalaxyCluster',
        'element' => 'galaxy',
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'data_path' => 'Event.date',
        'element' => 'datetime',
        'mode' => 'created',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Last Modified'),
        'data_path' => 'Event.timestamp',
        'element' => 'datetime',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Contents'),
        'data_path' => 'Event',
        'element' => 'event_contents',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Event.id',
        'publish_path' => 'Event.published',
        'card_section' => 'extra',
        'display_in' => ['table','card'],
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/events/view2/%id%'
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/events/edit/%id%',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/events/delete/%id%',
                'class' => 'text-danger',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => 'check_publish_rights'
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Unpublish'),
                'label_off' => __('Publish'),
                'icon_on' => 'eye-slash',
                'icon_off' => 'upload',
                'url' => $baseurl . '/events/%action%/%id%',
                'publish_path' => 'Event.published',
                'requirement' => 'check_publish_rights'
            ]
        ]
    ],
];

$children = [];

$children[] = [
    'type' => 'search',
    'button' => 'Search',
    'placeholder' => 'Search by info, ID or UUID',
    'name'        => 'eventinfo',
    'mode'        => 'event',
    'id_field'    => 'eventid',
];

if(!empty($show_user_button)) {
    $children[] = [
        'type' => 'button',
        'label' => __('My events'),
        'icon' => 'misp-icon misp-icon-user1 misp-simple',
        'class' => 'btn btn-primary',
        'url' => $baseurl . '/events/index/searchemail:' . urlencode($me['email'])
    ];
}

if(!empty($show_org_button)) {
    $children[] = [
        'type' => 'button',
        'label' => __('Org events'),
        'icon' => 'misp-icon misp-icon-organisation misp-simple',
        'class' => 'btn btn-primary',
        'url' => $baseurl . '/events/index/searchorg:' . urlencode($me['org_id'])
    ];
}


$children[] = [
    'type' => 'more_filters',
    'label' => __('More filters'),
    'children' => [
        [
            'type' => 'dropdown',
            'label' => __('Distribution'),
            'name' => 'distribution',
            'options' => [
                '' => '',
                '0' => 'Your organisation only',
                '1' => 'Community',
                '2' => 'Connected communities',
                '3' => 'All communities'
            ]
        ],
        [
            'type' => 'dropdown',
            'label' => __('Published'),
            'name' => 'published',
            'options' => [
                '' => '',
                '1' => 'Published',
                '0' => 'Not published'
            ]
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
            'data' => $events,
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxxxl' => 3],
            'filter_bar' => [
                'pull' => 'right',
                'children' => $children,
                'export' => 1,
                'delete' => '/delete'
            ],
            'fields' => $fields,
            'primary_id_path' => 'Event.id',
            'row_dblclick_url' => $baseurl . '/events/view2/%id%',
        ]
    ],
    'item_url' => '/events'
]);