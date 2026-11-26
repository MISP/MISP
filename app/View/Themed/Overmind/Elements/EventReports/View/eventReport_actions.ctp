<?php

$reportId = h($data['EventReport']['id'] ?? '');
$actions = [];

if (!empty($canEdit)) {
    $actions[] = ['divider' => true, 'label' => __('Content')];

    $actions[] = [
        'url' => "$baseurl/event_reports/edit/$reportId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/event_reports/edit/$reportId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Report'),
    ];

    $actions[] = [
        'url' => "$baseurl/event_reports/deleteSelection/$reportId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/event_reports/deleteSelection/$reportId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Report'),
        'danger' => true,
    ];
}

$actions[] = ['divider' => true, 'label' => __('Share')];

$actions[] = [
    'url' => "$baseurl/event_reports/download/$reportId",
    'onclick' => "erDownloadMarkdown('pdf-print', event);",
    'icon' => 'fas fa-print',
    'label' => __('Download PDF (via print)'),
];

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>
