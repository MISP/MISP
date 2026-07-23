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
        'name' => __('Event'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id, Event.info',
        'element' => 'event',
        'url' => $baseurl . '/events/view2/%event_id%',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Event.org_id',
        'data_path' => 'Event.Org',
        'element' => 'organisation',
        'card_section' => 'meta',
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
        'name' => __('Analyst data'),
        'element' => 'analyst_data_badges',
        'note_path' => 'EventReport.Note',
        'opinion_path' => 'EventReport.Opinion',
        'relationship_path' => 'EventReport.Relationship',
        'relationship_inbound_path' => 'EventReport.RelationshipInbound',
        'uuid_path' => 'EventReport.uuid',
        'object_type' => 'EventReport',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
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
            ],
            [
                'type' => 'divider',
                'requirement' => !empty($me['Role']['perm_analyst_data'])
            ],
            [
                'type' => 'modal',
                'label' => __('Add note'),
                'icon' => 'misp-icon misp-icon-analyst-note misp-simple',
                'url' => $baseurl . '/analystData/add/Note/%uuid%/EventReport',
                'url_params_data_paths' => ['uuid' => 'EventReport.uuid'],
                'requirement' => !empty($me['Role']['perm_analyst_data'])
            ],
            [
                'type' => 'modal',
                'label' => __('Add opinion'),
                'icon' => 'misp-icon misp-icon-analyst-opinion misp-simple',
                'url' => $baseurl . '/analystData/add/Opinion/%uuid%/EventReport',
                'url_params_data_paths' => ['uuid' => 'EventReport.uuid'],
                'requirement' => !empty($me['Role']['perm_analyst_data'])
            ],
            [
                'type' => 'modal',
                'label' => __('Add relationship'),
                'icon' => 'diagram-project',
                'url' => $baseurl . '/analystData/add/Relationship/%uuid%/EventReport',
                'url_params_data_paths' => ['uuid' => 'EventReport.uuid'],
                'requirement' => !empty($me['Role']['perm_analyst_data'])
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
