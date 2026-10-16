<?php
$SharingGroupId = h($data['SharingGroup']['id']);

$actions = [];


if ($editable) {
    $actions[] = [
        'url' => "$baseurl/SharingGroups/edit/$SharingGroupId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroups/edit/$SharingGroupId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit sharing group'),
        'short' => __('Edit')
    ];
}

if ($deletable) {
    $actions[] = [
        'url' => "$baseurl/SharingGroups/delete/$SharingGroupId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroups/deleteSelection/$SharingGroupId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete sharing group'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>