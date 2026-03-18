<?php
    echo $this->element('genericElements/assetLoader', [
        'css' => ['attack_matrix', 'analyst-data'],
        'js' => [
            'doT', 'd3', 'd3.custom',
            'network-distribution-graph',
        ],
    ]);
    $eventId = $event['Event']['id'];
    $pageTitle = h($event['Event']['info']);
    $mayModify = (
        $this->Acl->canAccess('events', 'edit') &&
        (
            $isSiteAdmin ||
            $event['Event']['orgc_id'] == $me['org_id']
        )
    );

    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'title' => $pageTitle,
        'data' => $event,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'info-circle',

                // Content
                'left' => [
                    'Events/View/event_general',
                    'Events/View/event_statistics'
                ],
                'right' => [
                    'Events/View/event_actions',
                    'Events/View/event_correlations',
                    'Events/View/event_warninglists'
                ]
            ],
            [
                'id' => 'objects',
                'title' => __('Objects'),
                'icon' => 'cube',
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
                        'ajax' => sprintf('/events/viewObjects/%s',h($eventId))
                    ]
                ],
            ],
            [
                'id' => 'attributes',
                'title' => __('Attributes'),
                'icon' => 'inbox',
                'count' => $attribute_count ?? 0,

                // Content
                'left' => [
                    [
                        // 'ajax' => $this->Url->build([
                        //     'controller' => 'events',
                        //     'action' => 'viewAttributes',
                        //     $eventId
                        // ])
                        'ajax' => sprintf('/events/viewAttributes/%s',h($eventId))
                    ]
                ],
            ],
            [
                'id' => 'reports',
                'title' => __('Reports'),
                'icon' => 'file-alt',
                'count' => $report_count ?? 0,

                // Content
                'left' => [
                    'Events/View/event_reports',
                ],
            ],
            [
                'id' => 'graph',
                'title' => __('Graph'),
                'icon' => 'project-diagram',

                // Content
                'left' => [
                    'Events/View/event_graph',
                ],
            ],
            [
                'id' => 'timeline',
                'title' => __('Timeline'),
                'icon' => 'clock',

                // Content
                'left' => [
                    'Events/View/event_timeline',
                ],
            ]
        ]
    ]);
?>

