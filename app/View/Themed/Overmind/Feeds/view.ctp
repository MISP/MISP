<?php
// Overmind BS5 single-view for a Feed.
$feed = $data['Feed'] ?? [];
$feedId = (int)($feed['id'] ?? 0);

$this->set('headerTitle', $feed['name'] ?? '');
$this->set('headerDescription', empty($feed['provider'])
    ? __('Feed source')
    : __('Provided by %s', $feed['provider']));

// Coverage is only meaningful once the feed has been cached into Redis.
$cachedElements = (int)($feed['cached_elements'] ?? 0);
$coverage = $feed['coverage_by_other_feeds'] ?? '0%';

$this->set('headerStats', [
    [
        'label' => __('Cached values'),
        'value' => number_format($cachedElements),
        'icon' => 'database',
        'color' => $cachedElements > 0 ? 'primary' : 'secondary',
        'subtitle' => $cachedElements > 0
            ? __('In the correlation cache')
            : __('Not cached yet'),
    ],
    [
        'label' => __('Covered by other feeds'),
        'value' => $coverage,
        'icon' => 'layer-group',
        'color' => 'info',
        'subtitle' => __('Share of the cached values seen elsewhere'),
    ],
    [
        'label' => __('Pulling'),
        'value' => !empty($feed['enabled']) ? __('Enabled') : __('Disabled'),
        'icon' => !empty($feed['enabled']) ? 'circle-play' : 'circle-stop',
        'color' => !empty($feed['enabled']) ? 'success' : 'secondary',
        'subtitle' => __('Events/attributes pulled into this instance'),
    ],
    [
        'label' => __('Caching'),
        'value' => !empty($feed['caching_enabled']) ? __('Enabled') : __('Disabled'),
        'icon' => 'bolt',
        'color' => !empty($feed['caching_enabled']) ? 'success' : 'secondary',
        'subtitle' => __('Feed values correlated without importing'),
    ],
]);

$tabs = [
    [
        'id' => 'general',
        'title' => __('General'),
        'icon' => 'fas fa-info-circle',
        'left' => [
            'Feeds/View/feeds_general',
            'Feeds/View/feeds_settings',
        ],
        'right' => [
            'Feeds/View/feeds_actions',
        ],
    ],
];

// The coverage tool compares this feed's cache against the other caching-enabled
// sources, so it has nothing to work with until this feed is itself cached.
if (!empty($feed['caching_enabled'])) {
    $tabs[] = [
        'id' => 'coverage',
        'title' => __('Coverage'),
        'icon' => 'fas fa-chart-pie',
        'left' => [
            'Feeds/View/feeds_coverage',
        ],
    ];
}

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => $tabs,
]);
