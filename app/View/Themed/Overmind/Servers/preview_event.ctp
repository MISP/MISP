<?php
/**
 *
 * Remote server event preview (Overmind).
 *
 */

$serverId   = (int)$server['Server']['id'];
$serverName = !empty($server['Server']['name'])
    ? sprintf('"%s" (%s)', $server['Server']['name'], $server['Server']['url'])
    : sprintf('"%s"', $server['Server']['url']);

$eventInfo = $event['Event']['info'] ?? '';

// Chart.js powers the attribute-stats donuts in the general card.
echo $this->element('genericElements/assetLoader', [
    'js' => ['Chart.min']
]);

$headerTitle = h($eventInfo);
$headerActions = [
    [
        'type' => 'navigate',
        'label' => __('Back to index'),
        'icon' => 'arrow-left',
        'url' => $baseurl . '/servers/previewIndex/' . $serverId
    ]
];
$this->set('headerTitle', $headerTitle);
$this->set('headerActions', $headerActions);

// rearrangeEventForView() merges attributes/objects/proposals into $event['objects']
// (each tagged with objectType) and unsets Event.Attribute. The Attributes tab
// shows standalone attributes; the Objects tab shows the object-type entries.
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
            <?= __('You are currently viewing an event on the remote instance %s', '<strong>' . h($serverName) . '</strong>') ?>
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
            'right' => [
                'Servers/View/preview_actions',
                'Servers/View/preview_related',
            ],
        ],
        [
            'id' => 'objects',
            'title' => __('Objects'),
            'icon' => 'misp-icon misp-icon-object misp-simple',
            'count' => $objectCount,
            'left' => [
                'Servers/View/preview_object',
            ],
        ],
        [
            'id' => 'attributes',
            'title' => __('Attributes'),
            'icon' => 'misp-icon misp-icon-attribute misp-simple',
            'count' => $attributeCount,
            'left' => [
                'Servers/View/preview_attributes',
            ],
        ],
    ]
]);
