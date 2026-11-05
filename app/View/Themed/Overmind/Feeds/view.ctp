<?php
// Overmind BS5 single-view for a Feed.
$feed = $data['Feed'] ?? [];
$feedId = (int)($feed['id'] ?? 0);
$railCards = $railCards ?? [];

$this->set('headerIdentity', $feed);
$this->set('headerTitle', $feed['name'] ?? '');

// The provider is the organisation the card names; the creator org the feed
// may force on pulled events is what its note says.
$provider = trim((string)($feed['provider'] ?? ''));
$orgc = $data['Orgc'] ?? [];
$pulledAs = empty($orgc['name'])
    ? __('pulled events keep their own creator organisation')
    : __('pulled events are created by %s', $orgc['name']);

$tabs = [
    [
        'id' => 'general',
        'title' => __('General'),
        'icon' => 'fas fa-info-circle',
        'left' => [
            'Feeds/View/feeds_general',
            'Feeds/View/feeds_settings',
        ],
        'right' => array_merge([
            'Feeds/View/feeds_actions',
        ], $this->RailCard->rail($railCards, [
            'feed-freshness', 'feed-overlap', 'feed-fetches',
        ], 'general')),
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
        'right' => $this->RailCard->rail($railCards, ['feed-overlap'], 'coverage'),
    ];
}

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'ownership' => [
        'orgc' => $provider === '' ? $orgc : ['name' => $provider],
        'orgNote' => $provider === '' ? '' : __('Provider') . ' · ' . $pulledAs,
        'noOrgText' => __('Pulled events keep their own creator organisation'),
        'distribution' => $feed['distribution'] ?? null,
        'sharingGroup' => $data['SharingGroup'] ?? [],
    ],
    'tabs' => $tabs,
]);
