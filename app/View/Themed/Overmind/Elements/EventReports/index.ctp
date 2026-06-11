<?php

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'EventReport.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'EventReport.id',
        'data_path' => 'EventReport.id',
        'element' => 'id',
        'url' => $baseurl . '/event_reports/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'EventReport.name',
        'data_path' => 'EventReport.name',
        'element' => 'report_value',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Event ID'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id, Event.info',
        'element' => 'id_name',
        'url' => $baseurl . '/events/view2/%event_id%',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Last Modified'),
        'data_path' => 'EventReport.timestamp',
        'element' => 'timestamp',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'EventReport.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/event_reports/view/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/event_reports/edit/%id%',
                'requirement' => $me['Role']['perm_add']
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/event_reports/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_add']
            ]
        ]
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $reports,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search by name or by content',
                        'name'        => 'value',
                        'mode'        => 'legacy',
                    ],
                ],
                'delete' => '/deleteSelection',
            ],
            'fields' => $fields,
            'primary_id_path' => 'EventReport.id',
            'row_dblclick_url' => $baseurl . '/event_reports/view/%id%',
        ]
    ],
    'item_url' => '/event_reports'
]);
