<?php
$this->set('headerIdentity', $event['Event']);
$this->set('headerTimestamps', $event['Event']);
$serverId   = (int)$server['Server']['id'];
$serverName = !empty($server['Server']['name'])
    ? sprintf('"%s" (%s)', $server['Server']['name'], $server['Server']['url'])
    : sprintf('"%s"', $server['Server']['url']);

$eventInfo = $event['Event']['info'] ?? '';

// Pulling requires the server to allow it, and only a site admin may do it.
$canPull = !empty($server['Server']['pull']) && !empty($isSiteAdmin);

echo $this->element('genericElements/assetLoader', [
    'js' => ['event-overview', 'objects-index'],
    // attributes-index, objects-index: the Attributes and Objects tabs.
    'css' => ['event-overview', 'attributes-index', 'objects-index'],
]);
$this->set('headerCountText', '');
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

$eventId = $event['Event']['id'] ?? '';

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
    <?= $this->element('genericElementsBS5/Layout/remote_notice', [
        'message' => __('You are currently viewing an event on the remote instance %s', '<strong>' . h($serverName) . '</strong>'),
    ]) ?>

</div>

<?php
echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $event,
    'ownership' => [
        'orgc' => $event['Orgc'] ?? [],
        'org' => $event['Org'] ?? [],
        'distribution' => $event['Event']['distribution'] ?? null,
        'sharingGroup' => $event['SharingGroup'] ?? [],
        'markings' => $previewOverview['markings'] ?? [],
        'link' => false,
    ],
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Events/View/overview_band',
                ['element' => 'Events/View/overview_facts', 'params' => ['overview' => $previewOverview]],
                ['element' => 'Events/View/overview_details', 'params' => ['activity' => false]],
            ],
            'right' => array_values(array_filter([
                $canPull ? 'Servers/View/preview_actions' : null,
                'Servers/View/preview_related',
            ])),
        ],
        [
            'id' => 'objects',
            'title' => __('Objects'),
            'icon' => 'misp-icon misp-icon-object misp-simple',
            'count' => $objectCount,
            'left' => [
                ['ajax' => $baseurl . '/servers/previewEventObjects/' . $serverId . '/' . h($eventId)],
            ],
        ],
        [
            'id' => 'attributes',
            'title' => __('Attributes'),
            'icon' => 'misp-icon misp-icon-attribute misp-simple',
            'count' => $attributeCount,
            'left' => [
                ['ajax' => $baseurl . '/servers/previewEventAttributes/' . $serverId . '/' . h($eventId)],
            ],
        ],
    ]
]);
