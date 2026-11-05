<?php
/*
 * The events a MISP feed's manifest lists, drawn as the events index draws its
 * own (the event_* field elements, events-index-table.css): FeedsController
 * hands each one over with its EventCard. A remote event has no local id, so
 * its title and actions go by uuid, and it has no publish state. A manifest
 * carries no counts either: the ones not cached yet are read from the feed
 * after the page is drawn (FeedsController::previewIndexCounts(), through
 * preview-index-counts.js).
 */
$feedId = (int)$feed['Feed']['id'];

$eventViewURL = $baseurl . '/feeds/previewEvent/' . $feedId . '/%id%';
// One and the same endpoint for a single row and for the toolbar selection: it
// renders the confirmation modal on GET and fetches on POST.
$massFetchURL = '/feeds/getSelectedEvents/' . $feedId;
$eventFetchURL = $baseurl . $massFetchURL . '/%id%';

// Fetching is only possible on an enabled feed, and only by a site admin.
$canFetch = !empty($feed['Feed']['enabled']) && !empty($isSiteAdmin);

$feedName = !empty($feed['Feed']['provider'])
    ? sprintf('%s (%s)', $feed['Feed']['name'], $feed['Feed']['provider'])
    : $feed['Feed']['name'];

$this->set('headerTitle', h($feed['Feed']['name']));
$this->set('headerDescription', __('Feed event index preview'));
$this->set('headerActions', [
    [
        'type' => 'navigate',
        'label' => __('Back to feeds'),
        'icon' => 'arrow-left',
        'url' => $baseurl . '/feeds/index'
    ]
]);

// The events index's column helpers (Elements/Events/index.ctp).
$col = function ($key, array $field, $class = '') {
    $class = trim('te-c-' . $key . ' ' . $class);
    return $field + [
        'class' => $class,
        'header_class' => $class,
        'display_in' => ['table'],
    ];
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
$count = function ($key, $count, $iconHtml, $title) use ($col) {
    return $col($key, [
        'element' => 'event_count',
        'count' => $count,
        'pending' => true,
        'header_html' => '<span class="te-hicon">' . $iconHtml . '</span>',
        'header_title' => $title,
    ], 'te-num');
};

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Event.uuid',
        'requirement' => $canFetch,
        'card_section' => 'selector',
        'class' => 'te-c-sel',
        'header_class' => 'te-c-sel',
    ],
    $col('title', [
        'name' => __('Title'),
        'sort' => 'info',
        'element' => 'event_title',
        'url' => $baseurl . '/feeds/previewEvent/' . $feedId . '/%uuid%',
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
    $count('attrs', 'attributes', '<i class="misp-icon misp-icon-attribute misp-simple text-attribute"></i>', __('Attributes')),
    $count('objs', 'objects', '<i class="misp-icon misp-icon-object misp-simple text-object"></i>', __('Objects')),
    $col('dist', [
        'element' => 'event_distribution',
        'header_html' => '<span class="te-hicon"><i class="fas fa-share-nodes"></i></span>',
        'header_title' => __('Distribution the fetched events get'),
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
        'data_path' => 'Event.uuid',
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
            $canFetch ? [
                'type' => 'modal',
                'label' => __('Fetch this event'),
                'icon' => 'circle-arrow-down',
                'url' => $eventFetchURL,
                'size' => 'md'
            ] : null,
        ]))
    ],
];

$filterBar = [
    // The bar's URLs are <item_url>/<action>: the preview's, positional feed id included.
    'action' => 'previewIndex/' . $feedId,
    'view_switch' => false,
    'children' => [[
        'type' => 'search',
        'mode' => 'legacy',
        'name' => 'searchall',
        'chip_label' => __('Search'),
        'placeholder' => __('Search by title, organisation, tag or UUID'),
    ]],
];
if ($canFetch) {
    $filterBar['fetch'] = true;
    $filterBar['fetch_url'] = $massFetchURL;
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
    'message' => __('You are currently viewing the event index of the feed %s', '<strong>' . h($feedName) . '</strong>'),
]) . '</div>';

printf(
    '<style class="te-colstyle"></style><div class="dk-index te-index" data-te="%s" data-counts-url="%s" data-counts-failed="%s">',
    h(json_encode($tableConfig)),
    h($baseurl . '/feeds/previewIndexCounts/' . $feedId),
    h(__('This event could not be read from the feed'))
);
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $events,
            'filter_bar' => $filterBar,
            'fields' => $fields,
            'primary_id_path' => 'Event.uuid',
            'row_dblclick_url' => $eventViewURL,
            'table_class' => 'te-table',
            'row_class_callable' => function ($row) {
                return 'te-row';
            },
            // The manifest timestamp keys a row's cached counts.
            'row_data_callable' => function ($row) {
                return ['ts' => (int)($row['Event']['timestamp'] ?? 0)];
            },
            // Positional feed id plus the named filter, so paging keeps both.
            'paginatorOptions' => [
                'url' => array_merge([$feedId], $this->request->params['named'])
            ],
        ]
    ],
    'item_url' => '/feeds'
]);
echo '</div>';
