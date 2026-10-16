<?php
$m = $modelSelection ?? 'Note';
$record = $data[$m] ?? [];
$recordId = h($record['id'] ?? '');

$actions = [];
if (!empty($mayModify)) {
    $actions[] = [
        'url' => "$baseurl/analystData/edit/$m/$recordId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/analystData/edit/$m/$recordId');",
        'icon' => 'fas fa-pen',
        'entity' => 'analystData',
        'label' => __('Edit %s', $m),
        'short' => __('Edit'),
    ];
    $actions[] = [
        'url' => "$baseurl/analystData/delete/$m/$recordId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/analystData/delete/$m/$recordId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete %s', $m),
        'danger' => true,
    ];
}
if (!empty($actions)) {
    echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
        'actions' => $actions,
    ]);
}

echo $this->element('AnalystData/rail_card', [
    'objectType' => $m,
    'objectUuid' => $record['uuid'] ?? '',
    'showThread' => false,
]);
