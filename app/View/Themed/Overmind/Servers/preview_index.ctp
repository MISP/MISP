<?php
/*
 * A remote instance's event index, drawn as the events index draws its own
 * (the event_* field elements, events-index-table.css): ServersController
 * hands each event over with its EventCard. The ids are the remote's: the
 * title, ID and actions open the remote event, and the remote index does the
 * filtering (Server::$validEventIndexFilters). It counts attributes only:
 * the object counts not cached yet are read off each event after the page is
 * drawn (ServersController::previewIndexCounts(), through
 * preview-index-counts.js).
 */
App::uses('EventCardTool', 'Tools/EventOverview');
$serverId = (int)$server['Server']['id'];
$serverName = !empty($server['Server']['name'])
    ? sprintf('"%s" (%s)', $server['Server']['name'], $server['Server']['url'])
    : sprintf('"%s"', $server['Server']['url']);

$eventViewURL = $baseurl . '/servers/previewEvent/' . $serverId . '/%id%';
// One and the same endpoint for a single row and for the toolbar selection: it
// renders the confirmation modal on GET and pulls on POST.
$massPullURL = '/servers/pullSelectedEvents/' . $serverId;
$eventPullURL = $baseurl . $massPullURL . '/%id%';

// Pulling requires the server to allow it, and only a site admin may do it.
$canPull = !empty($server['Server']['pull']) && !empty($isSiteAdmin);

$this->set('headerTitle', h($server['Server']['name'] ?: $server['Server']['url']));
$this->set('headerDescription', __('Remote instance event index preview'));
if (!empty($isSiteAdmin)) {
    $this->set('headerActions', [
        [
            'type' => 'navigate',
            'label' => __('Back to servers'),
            'icon' => 'arrow-left',
            'url' => $baseurl . '/servers/index'
        ]
    ]);
}

// The events index's column helpers (Elements/Events/index.ctp).
$col = function ($key, array $field, $class = '') {
    $class = trim('te-c-' . $key . ' ' . $class);
    return $field + [
        'class' => $class,
        'header_class' => $class,
        'display_in' => ['table'],
    ];
};
$icon = function ($html) {
    return '<span class="te-hicon">' . $html . '</span>';
};
$tagging = (bool)Configure::read('MISP.tagging');
$lane = function ($key, $lane, $title = null) use ($col, $tagging) {
    return $col($key, [
        'element' => 'event_lane',
        'lane' => $lane,
        'requirement' => $tagging,
        'header_html' => '<span class="te-lanecap"' . ($title ? ' title="' . h($title) . '"' : '') . '>'
            . $this->EventIndex->laneIcon($lane) . '<span>' . h($this->EventIndex->laneLabel($lane)) . '</span></span>',
    ], 'te-lane');
};

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Event.id',
        'remote' => true,
        'requirement' => $canPull,
        'card_section' => 'selector',
        'class' => 'te-c-sel',
        'header_class' => 'te-c-sel',
    ],
    $col('state', [
        'element' => 'event_state',
        'header_html' => $icon('<i class="fas fa-upload"></i>'),
        'header_title' => __('Publish state'),
    ]),
    $col('id', [
        'name' => __('ID'),
        'header_title' => __('ID on the remote instance'),
        'sort' => 'id',
        'data_path' => 'Event.id',
        'element' => 'id',
        'url' => $eventViewURL,
    ]),
    $col('title', [
        'name' => __('Title'),
        'sort' => 'info',
        'element' => 'event_title',
        'url' => $eventViewURL,
    ]),
    $col('orgc', [
        'header_html' => '<span class="te-long">' . h(__('Creator org')) . '</span><span class="te-short">' . h(__('Creator')) . '</span>',
        'element' => 'event_orgc',
    ]),
    $col('mk', [
        'name' => __('Markings'),
        'header_title' => __('Markings your analyst profile pins'),
        'element' => 'event_markings',
        'requirement' => $tagging,
    ]),
    $lane('attrib', 'attribution'),
    $lane('behav', 'behaviour', __('ATT&CK techniques, then mitigations')),
    $lane('classif', 'classification', __('Other clusters, then tags')),
    $col('attrs', [
        'element' => 'event_count',
        'count' => 'attributes',
        'header_html' => $icon('<i class="misp-icon misp-icon-attribute misp-simple text-attribute"></i>'),
        'header_title' => __('Attributes'),
    ], 'te-num'),
    $col('objs', [
        'element' => 'event_count',
        'count' => 'objects',
        'pending' => true,
        'header_html' => $icon('<i class="misp-icon misp-icon-object misp-simple text-object"></i>'),
        'header_title' => __('Objects'),
    ], 'te-num'),
    $col('dist', [
        'element' => 'event_distribution',
        'sort' => 'distribution',
        'header_html' => $icon('<i class="fas fa-share-nodes"></i>'),
        'header_title' => __('Distribution on the remote instance'),
    ]),
    $col('date', [
        'name' => __('Date'),
        'header_title' => __('Event date'),
        'sort' => 'date',
        'element' => 'event_date',
    ]),
    $col('changed', [
        'name' => __('Changed'),
        'header_title' => __('Last change'),
        'sort' => 'timestamp',
        'element' => 'event_changed',
    ]),
    [
        'element' => 'row_actions',
        'data_path' => 'Event.id',
        'class' => 'te-c-act',
        'header_class' => 'te-c-act',
        'display_in' => ['table'],
        'actions' => array_values(array_filter([
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $eventViewURL
            ],
            $canPull ? ['type' => 'divider'] : null,
            $canPull ? [
                'type' => 'modal',
                'label' => __('Fetch this event'),
                'icon' => 'circle-arrow-down',
                'url' => $eventPullURL,
                'size' => 'md',
                'requirement' => function ($row) {
                    return !empty($row['Event']['published']);
                }
            ] : null,
            // Same target, flagged: the remote has not published this one yet.
            $canPull ? [
                'type' => 'modal',
                'label' => __('Fetch this event (unpublished)'),
                'icon' => 'circle-arrow-down',
                'class' => 'text-warning',
                'url' => $eventPullURL,
                'size' => 'md',
                'requirement' => function ($row) {
                    return empty($row['Event']['published']);
                }
            ] : null,
        ]))
    ],
];

// The remote index's own filters, `search`-prefixed as the events index's are.
$levels = function (array $labels) {
    $options = [];
    foreach ($labels as $value => $label) {
        $options[] = ['value' => (string)$value, 'label' => $label];
    }
    return $options;
};
$distributionOptions = [];
foreach ([0, 1, 2, 3, 4] as $level) {
    $badge = EventCardTool::distribution($level);
    $distributionOptions[] = [
        'value' => (string)$level,
        'label' => $level === 4 ? __('Any sharing group') : ($distributionLevels[$level] ?? (string)$level),
        'style' => ['badge' => $badge['icon'], 'css' => $badge['style']],
    ];
}
$filterBar = [
    // The bar's URLs are <item_url>/<action>: the preview's, positional server id included.
    'action' => 'previewIndex/' . $serverId,
    'view_switch' => false,
    'children' => [
        [
            'type' => 'search',
            'mode' => 'event',
            'name' => 'all',
            'chip_label' => __('Search'),
            'placeholder' => __('Search the remote events: title, UUID, tag or value'),
        ],
        [
            'type' => 'picker',
            'name' => 'published',
            'label' => __('Published'),
            'icon' => 'fas fa-upload',
            'single' => true,
            'options' => [
                ['value' => '1', 'label' => __('Published'), 'style' => ['icon' => 'fas fa-circle-check']],
                ['value' => '0', 'label' => __('Unpublished'), 'style' => ['icon' => 'fas fa-file-pen']],
            ],
        ],
        [
            'type' => 'picker',
            'name' => 'distribution',
            'label' => __('Distribution'),
            'icon' => 'fas fa-share-nodes',
            'exclude' => true,
            'options' => $distributionOptions,
        ],
        [
            'type' => 'picker',
            'name' => 'threatlevel',
            'label' => __('Threat level'),
            'icon' => 'fas fa-gauge-high',
            'exclude' => true,
            'options' => $levels($threatLevels ?? []),
        ],
        [
            'type' => 'picker',
            'name' => 'analysis',
            'label' => __('Analysis'),
            'icon' => 'fas fa-magnifying-glass-chart',
            'exclude' => true,
            'options' => $levels($analysisLevels ?? []),
        ],
    ],
];
if ($canPull) {
    $filterBar['fetch'] = true;
    $filterBar['fetch_url'] = $massPullURL;
}

$tableConfig = [
    'hidden' => [],
    'saved' => null,
    'defaults' => [],
    'graded' => !empty(array_filter(array_map(function ($event) {
        return $event['EventCard']['grade'] ?? null;
    }, $events))),
];

echo $this->element('genericElements/assetLoader', [
    'css' => ['org-tile', 'events-index-cards', 'events-index-table'],
    'js' => ['events-index-cards', 'events-index-table', 'preview-index-counts'],
]);

echo '<div class="container-fluid">' . $this->element('genericElementsBS5/Layout/remote_notice', [
    'message' => __('You are currently viewing the event index of the remote instance %s', '<strong>' . h($serverName) . '</strong>'),
]) . '</div>';

printf(
    '<style class="te-colstyle"></style><div class="dk-index te-index" data-te="%s" data-counts-url="%s" data-counts-failed="%s">',
    h(json_encode($tableConfig)),
    h($baseurl . '/servers/previewIndexCounts/' . $serverId),
    h(__('This event could not be read from the remote instance'))
);
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $events,
            'filter_bar' => $filterBar,
            'fields' => $fields,
            'primary_id_path' => 'Event.id',
            'row_dblclick_url' => $eventViewURL,
            'table_class' => 'te-table',
            'row_class_callable' => function ($row) {
                return 'te-row';
            },
            // The remote timestamp keys a row's cached counts.
            'row_data_callable' => function ($row) {
                return ['ts' => (int)($row['Event']['timestamp'] ?? 0)];
            },
            // Positional server id plus the named filters, so paging keeps both.
            'paginatorOptions' => [
                'url' => array_merge([$serverId], $this->request->params['named'])
            ],
        ]
    ],
    'item_url' => '/servers'
]);
echo '</div>';
