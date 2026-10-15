<?php
    $headerTitle = __('') . ($event['Event']['info'] ?? '');
    $headerDescription = '';
    $headerActions = [];

    $canEdit = $isSiteAdmin || $this->Acl->canModifyEvent($event);
    if ($canEdit) {
        $headerActions[] = [
            'type' => 'modal',
            'tab' => 'attributes',
            'label' => __('Add attribute'),
            'icon' => 'plus',
            'url' => sprintf('%s/attributes/add/%s', $baseurl, h($event['Event']['id'])),
        ];

        $headerActions[] = [
            'type' => 'modal',
            'tab' => 'objects',
            'label' => __('Add object'),
            'icon' => 'plus',
            'url' => sprintf('%s/objects/add/%s', $baseurl, h($event['Event']['id'])),
        ];

        $headerActions[] = [
            'type' => 'modal',
            'tab' => 'reports',
            'label' => __('Add report'),
            'icon' => 'plus',
            'url' => sprintf('%s/event_reports/add/%s', $baseurl, h($event['Event']['id'])),
        ];
    }

    if ($this->Acl->canAccess('collectionElements', 'addElementToCollection')) {
        $headerActions[] = [
            'type' => 'modal',
            'tab' => 'general',
            'label' => __('Add to collection'),
            'icon' => 'folder-plus',
            'class' => 'btn btn-outline-dark',
            'url' => sprintf(
                '%s/collectionElements/addElementToCollection/Event/%s',
                $baseurl,
                h($event['Event']['uuid'])
            ),
            'size' => 'xl',
        ];
    }

    $this->set('headerTitle', $headerTitle);
    $this->set('headerBreadcrumbSuffix', '#' . $event['Event']['id']);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);

    $viewJs = ['markdown-it', 'font-awesome-helper', 'misp-report-markdown', 'event-report-reader', 'Chart.min',
        'event-overview', 'misp-matrix', 'misp-brush', 'misp-timeline', 'event-seen-timeline', 'tile-drawer',
        'event-object-views'];
    $viewCss = ['event-overview', 'misp-matrix', 'misp-brush', 'misp-timeline', 'value-widgets', 'tile-drawer',
        'event-object-views'];
    if (Configure::read('Plugin.Geolocation_enabled')) {
        $viewJs = array_merge($viewJs, ['leaflet', 'object-map']);
        $viewCss[] = 'leaflet';
    }
    echo $this->element('genericElements/assetLoader', [
        'js'  => $viewJs,
        'css' => $viewCss,
    ]);

    // Extended / extending view: say so, and carry the mode into every lazy
    // tab so a tab load never drops back to the atomic view.
    echo $this->element('Events/View/extension_banner');
    $extensionSuffix = $extensionSuffix ?? '';

    $searchFor = $this->request->params['named']['searchFor'] ?? '';
    $listSuffix = $extensionSuffix
        . ($searchFor !== '' ? '/searchFor:' . rawurlencode($searchFor) : '');
    $objectFilter = (int)($this->request->params['named']['object'] ?? 0);
    $objectsSuffix = $listSuffix . ($objectFilter > 0 ? '/object:' . $objectFilter : '');

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
                    'Events/View/overview_band',
                    'Events/View/overview_story',
                    'Events/View/overview_facts',
                    'Events/View/overview_annex',
                    'Events/View/overview_details',
                ],
                'right' => [
                    'Events/View/event_warnings',
                    'Events/View/event_actions',
                    'Events/View/event_matrix',
                    'Events/View/event_warninglists',
                    'Events/View/event_sightings',
                    'Events/View/event_related',
                    'Events/View/event_collections',
                    'Events/View/event_graphs',
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
                        'ajax' => sprintf('/events/viewObjects/%s%s', h($event['Event']['id']), $objectsSuffix)
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
                        'ajax' => sprintf('/events/viewAttributes/%s%s', h($event['Event']['id']), $listSuffix)
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
                'iconColor' => 'var(--bs-correlation)',
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

                // Content
                'left' => [
                    'Events/View/event_history',
                ]
            ]
        ]
    ]);

    echo $this->element('Events/View/report_reader');
?>

