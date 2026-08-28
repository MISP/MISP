<?php

    $headerTitle = __('') . ($event['Event']['info'] ?? '');
    $headerDescription = '';
    $headerActions = [];
    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);

    echo $this->element('genericElements/assetLoader', [
        'js'  => ['markdown-it', 'Chart.min']
    ]);

    // Extended / extending view: say so, and carry the mode into every lazy
    // tab so a tab load never drops back to the atomic view.
    echo $this->element('Events/View/extension_banner');
    $extensionSuffix = $extensionSuffix ?? '';

    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $event,
        'report' => $event['EventReport'] ?? null,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'fas fa-info-circle',

                // Content
                'left' => [
                    'Events/View/event_general',
                    'EventReports/View/eventReport_preview',
                    'Events/View/event_tags',
                    'Events/View/event_galaxies',
                    'Events/View/event_attachments',
                ],
                'right' => [
                    'Events/View/event_actions',
                    'Events/View/event_analyst_data',
                    'Events/View/event_sightings',
                    'Events/View/event_related',
                    'Events/View/event_warninglists',
                    'Events/View/event_collections',
                ]
            ],
            [
                'id' => 'objects',
                'title' => __('Objects'),
                'icon' => 'misp-icon misp-icon-object misp-simple',
                'count' => $object_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/events/viewObjects/%s%s', h($event['Event']['id']), $extensionSuffix)
                    ]
                ],
            ],
            [
                'id' => 'attributes',
                'title' => __('Attributes'),
                'icon' => 'misp-icon misp-icon-attribute misp-simple',
                'count' => $attribute_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/events/viewAttributes/%s%s', h($event['Event']['id']), $extensionSuffix)
                    ]
                ],
            ],
            [
                'id' => 'reports',
                'title' => __('Reports'),
                'icon' => 'misp-icon misp-icon-report misp-simple',
                'count' => $report_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/events/viewEventReports/%s%s', h($event['Event']['id']), $extensionSuffix)
                    ]
                ],
            ],
            [
                'id' => 'correlation',
                'title' => __('Correlation'),
                'icon' => 'fas fa-link',
                'count' => $correlation_count ?? 0,

                // Content
                'left' => [
                    'Events/View/event_correlation_graph',
                ],
            ],
            [
                'id' => 'pivot-explorer',
                'title' => __('Pivot Explorer'),
                'icon' => 'fas fa-circle-nodes',

                // Content
                'left' => [
                    'Events/View/event_pivot_explorer',
                ],
            ],
            // [
            //     'id' => 'timeline',
            //     'title' => __('Timeline'),
            //     'icon' => 'fas fa-clock',

            //     // Content
            //     'left' => [
            //         'Events/View/event_timeline',
            //     ],
            // ],
            [
                'id' => 'history',
                'title' => __('History'),
                'icon' => 'fas fa-history',

                // Content
                'left' => [
                    'Events/View/event_history',
                ]
            ]
        ]
    ]);
?>

