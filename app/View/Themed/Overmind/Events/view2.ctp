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
                    'Events/View/event_sightings',
                    'Events/View/event_related',
                    'Events/View/event_warninglists',
                ]
            ],
            [
                'id' => 'objects',
                'title' => __('Objects'),
                'icon' => 'misp-icon misp-icon-object misp-simple',
                //For the moment the view2 controller doesn't return object_count/attribute_count
                'count' => $object_count ?? 0,

                // Content
                'left' => [
                    [
                        // 'ajax' => $this->Url->build([
                        //     'controller' => 'events',
                        //     'action' => 'viewObjects',
                        //     $eventId
                        // ])
                        'ajax' => sprintf('/events/viewObjects/%s',h($event['Event']['id']))
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
                        // 'ajax' => $this->Url->build([
                        //     'controller' => 'events',
                        //     'action' => 'viewAttributes',
                        //     $eventId
                        // ])
                        'ajax' => sprintf('/events/viewAttributes/%s',h($event['Event']['id']))
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
                        'ajax' => sprintf('/events/viewEventReports/%s', h($event['Event']['id']))
                    ]
                ],
            ],
            [
                'id' => 'graph',
                'title' => __('Graph'),
                'icon' => 'fas fa-project-diagram',

                // Content
                'left' => [
                    'Events/View/event_graph',
                ],
            ],
            [
                'id' => 'timeline',
                'title' => __('Timeline'),
                'icon' => 'fas fa-clock',

                // Content
                'left' => [
                    'Events/View/event_timeline',
                ],
            ],
            [
                'id' => 'history',
                'title' => __('History'),
                'icon' => 'fas fa-history',
                'count' => $history_count ?? 0,

                // Content
                'left' => [
                    'Events/View/event_history',
                ]
            ]
        ]
    ]);
?>

