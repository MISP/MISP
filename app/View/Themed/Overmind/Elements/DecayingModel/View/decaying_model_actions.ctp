<?php
$dm = $data['DecayingModel'];
$id = h($dm['id']);
$editable = !empty($dm['isEditable']);
$isDefault = !empty($dm['default']);

$actions = [];

if ($editable) {
    $actions[] = [
        'url' => "$baseurl/decayingModel/edit/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/decayingModel/edit/$id');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit model'),
    ];
}

// $actions[] = [
//     'url' => "$baseurl/decayingModel/decayingTool",
//     'icon' => 'fas fa-wave-square',
//     'label' => __('Open in Decaying Tool'),
// ];

// $actions[] = [
//     'url' => "$baseurl/decayingModel/decayingToolSimulation/$id",
//     'icon' => 'fas fa-chart-line',
//     'label' => __('Simulate model'),
// ];

$actions[] = [
    'url' => "$baseurl/decayingModel/export/$id.json",
    'icon' => 'fas fa-cloud-arrow-down',
    'label' => __('Download JSON'),
];

if ($editable) {
    if (empty($dm['enabled'])) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/decayingModel/enable/$id",
            'id' => $id,
            'icon' => 'fas fa-play',
            'label' => __('Enable model'),
            'success' => true,
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/decayingModel/disable/$id",
            'id' => $id,
            'icon' => 'fas fa-pause',
            'label' => __('Disable model'),
            'warning' => true,
        ];
    }

    if (!$isDefault) {
        $actions[] = [
            'url' => "$baseurl/decayingModel/deleteSelection/$id",
            'onclick' => "event.preventDefault(); openModal('$baseurl/decayingModel/deleteSelection/$id', 'sm');",
            'icon' => 'fas fa-trash',
            'label' => __('Delete model'),
            'danger' => true,
        ];
    }
}

echo $this->element('genericElementsBS5/Cards/card_actions', ['actions' => $actions]);
