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
];

if ($siteAdmin && $isEnabled) {
    $actions[] = [
        'url' => "$baseurl/feeds/fetchSelectedFeeds/$feedId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/feeds/fetchSelectedFeeds/$feedId', 'sm');",
        'icon' => 'fas fa-circle-arrow-down',
        'label' => __('Fetch all events'),
        'success' => true,
    ];
}

if ($siteAdmin) {
    $actions[] = $isEnabled
        ? [
            'url' => "$baseurl/feeds/disable/$feedId",
            'type' => 'post',
            'icon' => 'fas fa-stop',
            'label' => __('Disable feed'),
            'warning' => true,
        ]
        : [
            'url' => "$baseurl/feeds/enable/$feedId",
            'type' => 'post',
            'icon' => 'fas fa-play',
            'label' => __('Enable feed'),
            'success' => true,
        ];

    $actions[] = [
        'url' => "$baseurl/feeds/edit/$feedId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/feeds/edit/$feedId');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Edit feed'),
    ];
}

$actions[] = [
    'url' => "$baseurl/feeds/view/$feedId.json",
    'icon' => 'fas fa-cloud-arrow-down',
    'label' => __('Download metadata as JSON'),
];

if ($siteAdmin) {
    $actions[] = [
        'url' => "$baseurl/feeds/deleteSelection/$feedId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/feeds/deleteSelection/$feedId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete feed'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
