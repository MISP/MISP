<?php
// Overmind BS5 index for Feeds. Mirrors the legacy Default index (columns +
// scope toggle + quickFilter search + row actions), minus the OUT-of-scope
// mass enable/disable/caching toolbar, preview/fetch actions and cache-all
// header buttons (feature pages tracked in the parent plan, not the CRUD port).
$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$distributionLevels = $this->viewVars['distributionLevels'] ?? [];

$headerActions = [];
if ($isSiteAdmin) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Feed'),
        'icon' => 'plus',
        'url' => $baseurl . '/feeds/add',
    ];
}
$this->set('headerTitle', __('Feeds'));
$this->set('headerDescription', __('Feed sources that can be pulled into this instance as events/attributes or cached for correlation.'));
$this->set('headerActions', $headerActions);

$fields = [
    [
        'name' => __('ID'),
        'sort' => 'Feed.id',
        'data_path' => 'Feed.id',
        'element' => 'id',
        'url' => $baseurl . '/feeds/view/%id%',
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'Feed.enabled',
        'data_path' => 'Feed.enabled',
        'element' => 'flag',
    ],
    [
        'name' => __('Caching'),
        'sort' => 'Feed.caching_enabled',
        'data_path' => 'Feed.caching_enabled',
        'element' => 'flag',
    ],
    [
        'name' => __('Name'),
        'sort' => 'Feed.name',
        'data_path' => 'Feed.name',
    ],
    [
        'name' => __('Format'),
        'sort' => 'Feed.source_format',
        'data_path' => 'Feed.source_format',
    ],
    [
        'name' => __('Provider'),
        'sort' => 'Feed.provider',
        'data_path' => 'Feed.provider',
    ],
    [
        'name' => __('Org'),
        'sort' => 'Feed.orgc_id',
        'data_path' => 'Orgc',
        'element' => 'organisation',
    ],
    [
        'name' => __('Source'),
        'sort' => 'Feed.input_source',
        'data_path' => 'Feed.input_source',
    ],
    [
        'name' => __('URL'),
        'sort' => 'Feed.url',
        'data_path' => 'Feed.url',
        'class' => 'quickSelect',
    ],
    [
        'name' => __('Headers'),
        'data_path' => 'Feed.headers',
        'requirement' => $isSiteAdmin,
    ],
    [
        'name' => __('Target'),
        'element' => 'custom',
        // Mirrors genericElements/IndexTable/Fields/target_event.ctp
        'function' => function (array $row) use ($baseurl) {
            $feed = $row['Feed'];
            if (empty($feed['enabled'])) {
                return __('Feed not enabled');
            }
            if (!in_array($feed['source_format'], ['freetext', 'csv'], true)) {
                return '';
            }
            if (empty($feed['fixed_event'])) {
                return sprintf(
                    '<span class="text-danger fw-semibold" title="%s">%s</span>',
                    h(__('New event each pull can lead to potentially endlessly growing correlation tables. Only use this setting if you are sure that the data in the feed will mostly be completely distinct between each individual pull, otherwise use fixed events. Generally this setting is NOT recommended.')),
                    __('New event each pull')
                );
            }
            if (!empty($feed['event_error'])) {
                return sprintf('<span class="text-danger fw-semibold">%s</span>', __('Error: Invalid event!'));
            }
            if (!empty($feed['event_id'])) {
                return sprintf(
                    '<a href="%s/events/view/%s">%s</a>',
                    h($baseurl),
                    h($feed['event_id']),
                    __('Fixed event %s', h($feed['event_id']))
                );
            }
            return __('New fixed event');
        },
    ],
    [
        'name' => __('Publish'),
        'sort' => 'Feed.publish',
        'data_path' => 'Feed.publish',
        'element' => 'flag',
    ],
    [
        'name' => __('Delta'),
        'sort' => 'Feed.delta_merge',
        'data_path' => 'Feed.delta_merge',
        'element' => 'flag',
    ],
    [
        'name' => __('Override'),
        'sort' => 'Feed.ids',
        'data_path' => 'Feed.ids',
        'element' => 'flag',
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'Feed.distribution',
        'element' => 'distribution',
    ],
    [
        'name' => __('Tag'),
        'element' => 'custom',
        'function' => function (array $row) {
            $out = '';
            if (!empty($row['Tag']['id'])) {
                $out .= $this->element('genericElementsBS5/Badges/tag', [
                    'tag' => $row['Tag'],
                    'local' => false,
                    'showFavourite' => false,
                ]);
            }
            if (!empty($row['TagCollection'])) {
                $tc = $row['TagCollection'];
                $name = $tc['TagCollection']['name'] ?? ($tc['name'] ?? '');
                if ($name !== '') {
                    $out .= sprintf('<span class="badge text-bg-info ms-1" title="%s">%s</span>', h(__('Tag collection')), h($name));
                }
            }
            return $out;
        },
    ],
    [
        'name' => __('Visible'),
        'sort' => 'Feed.lookup_visible',
        'data_path' => 'Feed.lookup_visible',
        'element' => 'flag',
    ],
    [
        'name' => __('Caching'),
        'requirement' => $isSiteAdmin,
        'element' => 'custom',
        'function' => function (array $row) {
            if (empty($row['Feed']['caching_enabled'])) {
                return '<span class="text-muted">-</span>';
            }
            $ts = $row['Feed']['cache_timestamp'] ?? null;
            if (empty($ts)) {
                return sprintf('<span class="text-muted">%s</span>', __('Never'));
            }
            return sprintf(
                '<span title="%s">%s</span>',
                h(date('Y-m-d H:i:s', (int)$ts)),
                h(date('Y-m-d H:i', (int)$ts))
            );
        },
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Feed.id',
        'actions' => array_values(array_filter([
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/feeds/view/%id%',
            ],
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/feeds/edit/%id%',
            ] : null,
            $isSiteAdmin ? [
                'type' => 'postLink',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/feeds/delete/%id%',
                'class' => 'text-danger',
                'confirm' => __('Are you sure you want to permanently remove the feed?'),
            ] : null,
            [
                'type' => 'navigate',
                'label' => __('Download feed metadata as JSON'),
                'icon' => 'cloud-arrow-down',
                'url' => $baseurl . '/feeds/view/%id%.json',
                'download' => true,
            ],
        ])),
    ],
];

// Scope toggle (default / custom / all / enabled) mirrors the legacy top bar.
// Each is a fresh navigation carrying the scope in the URL path.
$scope = $this->viewVars['scope'] ?? 'all';
$scopeButtons = [
    ['label' => __('Default feeds'), 'value' => 'default', 'url' => $baseurl . '/feeds/index/scope:default'],
    ['label' => __('Custom feeds'), 'value' => 'custom', 'url' => $baseurl . '/feeds/index/scope:custom'],
    ['label' => __('All feeds'), 'value' => 'all', 'url' => $baseurl . '/feeds/index/scope:all'],
    ['label' => __('Enabled feeds'), 'value' => 'enabled', 'url' => $baseurl . '/feeds/index/scope:enabled'],
];
$filterChildren = [];
foreach ($scopeButtons as $button) {
    $filterChildren[] = [
        'type' => 'button',
        'label' => $button['label'],
        'url' => $button['url'],
        'class' => 'btn btn-sm ' . ($scope === $button['value'] ? 'btn-primary' : 'btn-outline-primary'),
    ];
}
$filterChildren[] = [
    'type' => 'search',
    'mode' => 'quickFilter',
    'button' => __('Filter'),
    'placeholder' => __('Enter value to search'),
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'Feed.id',
            'row_dblclick_url' => $baseurl . '/feeds/view/%id%',
            'filter_bar' => [
                'pull' => 'right',
                'children' => $filterChildren,
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/feeds',
]);
