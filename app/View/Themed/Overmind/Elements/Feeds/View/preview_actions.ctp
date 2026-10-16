<?php

$ctx = $previewContext ?? [];
$fetchUrl = $ctx['fetchUrl'] ?? null;
if (empty($fetchUrl)) {
    return;
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => [
        [
            'url' => $fetchUrl,
            'icon' => 'fas fa-circle-arrow-down',
            'entity' => 'event',
            'label' => __('Fetch this event'),
            'short' => __('Fetch'),
            'onclick' => sprintf(
                "event.preventDefault(); openModal('%s', 'md');",
                h($fetchUrl)
            ),
        ],
    ]
]);
