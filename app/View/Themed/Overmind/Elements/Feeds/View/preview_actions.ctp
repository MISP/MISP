<?php

$ctx = $previewContext ?? [];
$fetchUrl = $ctx['fetchUrl'] ?? null;
if (empty($fetchUrl)) {
    return;
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => [
        [
            'url' => $fetchUrl,
            'icon' => 'fas fa-circle-arrow-down',
            'label' => __('Fetch this event'),
            'success' => true,
            'onclick' => sprintf(
                "event.preventDefault(); openModal('%s', 'sm');",
                h($fetchUrl)
            ),
        ],
    ]
]);
