<?php
$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$distributionLevels = $this->viewVars['distributionLevels'] ?? [];

$headerActions = [];
if ($isSiteAdmin) {
    /*
     * Instance-wide feed operations, grouped so they don't crowd the header.
     * All of them are POSTed rather than linked: they enqueue background jobs or
     * write feed definitions, so they have no business being reachable by GET.
     * Fetching every feed goes through the same confirmation modal as the row
     * and toolbar actions, with `all` standing in for the selection.
     */
    $headerActions[] = [
        'type' => 'dropdown',
        'label' => __('Feed operations'),
        'icon' => 'gears',
        'children' => [
            [
                'type' => 'action',
                'label' => __('Load default feed metadata'),
                'icon' => 'download',
                'url' => $baseurl . '/feeds/loadDefaultFeeds',
                'confirm' => __('Add the feed definitions shipped with MISP? Existing feeds are left untouched.'),
            ],
            ['type' => 'divider'],
            [
                'type' => 'action',
                'label' => __('Cache all feeds'),
                'icon' => 'bolt',
                'url' => $baseurl . '/feeds/cacheFeeds/all',
            ],
            [
                'type' => 'action',
                'label' => __('Cache freetext/CSV feeds'),
                'icon' => 'bolt',
                'url' => $baseurl . '/feeds/cacheFeeds/freetext',
            ],
            [
                'type' => 'action',
                'label' => __('Cache MISP feeds'),
                'icon' => 'bolt',
                'url' => $baseurl . '/feeds/cacheFeeds/misp',
            ],
            ['type' => 'divider'],
            [
                'type' => 'modal',
                'label' => __('Fetch and store all feed data'),
                'icon' => 'circle-arrow-down',
                'url' => $baseurl . '/feeds/fetchSelectedFeeds/all',
                'size' => 'sm',
            ],
        ],
    ];
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Import JSON'),
        'icon' => 'file-import',
        'url' => $baseurl . '/feeds/importFeeds',
    ];
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


$yesNoOptions = ['' => '', '1' => __('Yes'), '0' => __('No')];

$filterChildren = [
    [
        'type' => 'search',
        'button' => __('Search'),
        'placeholder' => __('Search by name, URL, provider or format'),
        'mode' => 'quickFilter',
    ],
    [
        'type' => 'more_filters',
        'label' => __('More filters'),
        'children' => [
            [
                'type' => 'dropdown',
                'label' => __('Enabled'),
                'name' => 'enabled',
                'options' => $yesNoOptions,
            ],
            [
                'type' => 'dropdown',
                'label' => __('Caching enabled'),
                'name' => 'caching_enabled',
                'options' => $yesNoOptions,
            ],
            [
                'type' => 'dropdown',
                'label' => __('Source format'),
                'name' => 'source_format',
                'options' => ['' => ''] + ($feedTypeOptions ?? []),
            ],
            [
                'type' => 'dropdown',
                'label' => __('Input source'),
                'name' => 'input_source',
                'options' => ['' => ''] + ($inputSourceOptions ?? []),
            ],
            [
                'type' => 'dropdown',
                'label' => __('Distribution'),
                'name' => 'distribution',
                'options' => ['' => ''] + $distributionLevels,
            ],
            [
                'type' => 'dropdown',
                'label' => __('Default feed'),
                'name' => 'default',
                'options' => $yesNoOptions,
            ],
            [
                'type' => 'dropdown',
                'label' => __('Visible to all orgs'),
                'name' => 'lookup_visible',
                'options' => $yesNoOptions,
            ],
        ],
    ],
];

/*
 * Provider and creator org are data-driven, so they are only offered when the
 * visible feeds actually give something to choose from — default feeds carry no
 * orgc_id, which would otherwise leave an empty dropdown on a stock instance.
 */
if (!empty($providerOptions)) {
    $filterChildren[1]['children'][] = [
        'type' => 'dropdown',
        'label' => __('Provider'),
        'name' => 'provider',
        'options' => ['' => ''] + $providerOptions,
    ];
}
if (!empty($orgOptions)) {
    $filterChildren[1]['children'][] = [
        'type' => 'dropdown',
        'label' => __('Creator org'),
        'name' => 'orgc_id',
        'options' => ['' => ''] + $orgOptions,
    ];
}

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Feed.id',
        'enable_path' => 'Feed.enabled',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Feed.id',
        'data_path' => 'Feed.id',
        'element' => 'id',
        'url' => $baseurl . '/feeds/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'Feed.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Feed.name',
        'data_path' => 'Feed.name',
        'element' => 'feed_name',
        'distribution_path' => 'Feed.distribution',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'Feed.enabled',
        'data_path' => 'Feed.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Provider'),
        'sort' => 'Feed.provider',
        'data_path' => 'Feed.provider',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Org'),
        'sort' => 'Feed.orgc_id',
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Source'),
        'sort' => 'Feed.source_format',
        'data_path' => 'Feed.source_format',
        'element' => 'feed_source',
        'input_source_path' => 'Feed.input_source',
        'headers_path' => $isSiteAdmin ? 'Feed.headers' : null,
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('URL'),
        'sort' => 'Feed.url',
        'data_path' => 'Feed.url',
        'element' => 'links',
        'card_section' => 'links',
        'display_in' => ['table', 'card'],
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
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'Tag',
        'tag_collection_path' => 'TagCollection',
        'element' => 'tag_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Delta'),
        'sort' => 'Feed.delta_merge',
        'data_path' => 'Feed.delta_merge',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Override IDS'),
        'sort' => 'Feed.ids',
        'data_path' => 'Feed.ids',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Publish'),
        'sort' => 'Feed.publish',
        'data_path' => 'Feed.publish',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Visible'),
        'sort' => 'Feed.lookup_visible',
        'data_path' => 'Feed.lookup_visible',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Caching'),
        'sort' => 'Feed.caching_enabled',
        'data_path' => 'Feed.caching_enabled',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
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
        'card_section' => 'meta',
        'display_in' => ['card']
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
            [
                'type' => 'navigate',
                'label' => __('Explore the events remotely'),
                'icon' => 'magnifying-glass',
                'url' => $baseurl . '/feeds/previewIndex/%id%',
            ],
            [
                'type' => 'navigate',
                'label' => __('Download feed metadata as JSON'),
                'icon' => 'cloud-arrow-down',
                'url' => $baseurl . '/feeds/view/%id%.json',
                'download' => true,
            ],
            $isSiteAdmin ? [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'fas fa-stop text-danger',
                'icon_off' => 'fas fa-play text-success',
                'url' => $baseurl . '/feeds/%action%/%id%',
                'state_path' => 'Feed.enabled',
                'action_on' => 'disable',
                'action_off' => 'enable',
            ] : null,
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Fetch all events'),
                'icon' => 'circle-arrow-down',
                'url' => $baseurl . '/feeds/fetchSelectedFeeds/%id%',
                'size' => 'sm',
                'requirement' => function (array $row) {
                    return !empty($row['Feed']['enabled']);
                },
            ] : null,
            $isSiteAdmin ? [ 'type' => 'divider'] : null,
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/feeds/edit/%id%',
            ] : null,
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/feeds/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ])),
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
];


echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => $filterChildren,
                'delete' => '/deleteSelection',
                'fetch' => $isSiteAdmin ? '/fetchSelectedFeeds' : null,
                'enable' => $isSiteAdmin ? true : null,
                'enable_url' => '/feeds/toggleSelected/1/0',
                'disable_url' => '/feeds/toggleSelected/0/0',
            ],
            'fields' => $fields,
            'primary_id_path' => 'Feed.id',
            'row_dblclick_url' => $baseurl . '/feeds/view/%id%',
        ],
    ],
    'item_url' => '/feeds',
]);
