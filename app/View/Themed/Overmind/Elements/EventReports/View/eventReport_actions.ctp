<?php

$reportId = h($data['EventReport']['id'] ?? '');
$actions = [];

if (!empty($canEdit)) {
    $actions[] = [
        'url' => "$baseurl/event_reports/edit/$reportId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/event_reports/edit/$reportId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Report'),
    ];
}

if (!empty($canEdit)) {
    $actions[] = [
        'url' => "$baseurl/event_reports/view/$reportId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/event_reports/deleteSelection/$reportId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Report'),
        'danger' => true,
    ];
}


echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>
