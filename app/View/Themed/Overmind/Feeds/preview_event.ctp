<?php

$feedId = (int)$feed['Feed']['id'];
$feedName = !empty($feed['Feed']['provider'])
    ? sprintf('%s (%s)', $feed['Feed']['name'], $feed['Feed']['provider'])
    : $feed['Feed']['name'];

$eventUuid = $event['Event']['uuid'] ?? '';
$previewIndexUrl = $baseurl . '/feeds/previewIndex/' . $feedId;

// Fetching is only possible on an enabled feed, and only by a site admin.
$canFetch = !empty($feed['Feed']['enabled']) && !empty($isSiteAdmin);

echo $this->element('genericElements/assetLoader', [
    'js' => ['Chart.min']
]);

$this->set('headerTitle', h($event['Event']['info'] ?? ''));

$this->set('headerCountText', '');
$this->set('headerActions', [
    [
        'type' => 'navigate',
        'label' => __('Back to index'),
        'icon' => 'arrow-left',
        'url' => $previewIndexUrl
    ]
]);

// rearrangeEventForView() merges attributes/objects/proposals into $event['objects'] (each tagged with objectType) 
$attributeCount = 0;
$objectCount = 0;
foreach ($event['objects'] ?? [] as $previewObject) {
    $objectType = $previewObject['objectType'] ?? '';
    if ($objectType === 'attribute') {
        $attributeCount++;
    } elseif ($objectType === 'object') {
        $objectCount++;
    }
}
?>

<div class="container-fluid">
    <div class="alert alert-warning d-flex align-items-center gap-2 shadow-sm" role="alert">
        <i class="fas fa-satellite-dish fs-4"></i>
        <div>
            <?= __('You are currently viewing an event from the feed %s', '<strong>' . h($feedName) . '</strong>') ?>
        </div>
    </div>
</div>

<?php
echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $event,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Servers/View/preview_general',
                'Servers/View/preview_tags',
                'Servers/View/preview_galaxies',
            ],
            'right' => array_values(array_filter([
                $canFetch ? 'Feeds/View/preview_actions' : null,
                'Servers/View/preview_related',
            ])),
        ],
        [
            'id' => 'objects',
            'title' => __('Objects'),
            'icon' => 'misp-icon misp-icon-object misp-simple',
            'count' => $objectCount,
            'left' => [
                ['ajax' => $baseurl . '/feeds/previewEventObjects/' . $feedId . '/' . h($eventUuid)],
            ],
        ],
        [
            'id' => 'attributes',
            'title' => __('Attributes'),
            'icon' => 'misp-icon misp-icon-attribute misp-simple',
            'count' => $attributeCount,
            'left' => [
                ['ajax' => $baseurl . '/feeds/previewEventAttributes/' . $feedId . '/' . h($eventUuid)],
            ],
        ],
    ]
]);
