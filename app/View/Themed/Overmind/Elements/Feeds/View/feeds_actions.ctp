<?php
$feed = $data['Feed'] ?? [];
$feedId = (int)($feed['id'] ?? 0);
$isEnabled = !empty($feed['enabled']);
$siteAdmin = !empty($isSiteAdmin);

$actions = [];

$actions[] = [
    'url' => "$baseurl/feeds/previewIndex/$feedId",
    'icon' => 'fas fa-magnifying-glass',
    'label' => __('Explore the events remotely'),
    'short' => __('Explore'),
];

if ($siteAdmin && $isEnabled) {
    $actions[] = [
        'url' => "$baseurl/feeds/fetchSelectedFeeds/$feedId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/feeds/fetchSelectedFeeds/$feedId', 'md');",
        'icon' => 'fas fa-circle-arrow-down',
        'entity' => 'event',
        'label' => __('Fetch all events'),
        'short' => __('Fetch all'),
    ];
}

if ($siteAdmin) {
    $actions[] = $isEnabled
        ? [
            'url' => "$baseurl/feeds/disable/$feedId",
            'type' => 'post',
            'icon' => 'fas fa-toggle-off',
            'label' => __('Disable feed'),
            'short' => __('Disable'),
        ]
        : [
            'url' => "$baseurl/feeds/enable/$feedId",
            'type' => 'post',
            'icon' => 'fas fa-toggle-on',
            'label' => __('Enable feed'),
            'short' => __('Enable'),
        ];

    $actions[] = [
        'url' => "$baseurl/feeds/edit/$feedId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/feeds/edit/$feedId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit feed'),
        'short' => __('Edit'),
    ];
}

$actions[] = [
    'url' => "$baseurl/feeds/view/$feedId.json",
    'icon' => 'fas fa-download',
    'label' => __('Download metadata as JSON'),
    'short' => __('Download'),
];

if ($siteAdmin) {
    $actions[] = [
        'url' => "$baseurl/feeds/deleteSelection/$feedId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/feeds/deleteSelection/$feedId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete feed'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
