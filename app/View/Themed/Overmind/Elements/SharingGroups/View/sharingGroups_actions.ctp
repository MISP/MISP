<?php
$SharingGroupId = h($data['SharingGroup']['id']);

$actions = [];


if ($editable) {
    $actions[] = [
        'url' => "$baseurl/SharingGroups/edit/$SharingGroupId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroups/edit/$SharingGroupId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit SharingGroup')
    ];
}

if ($deletable) {
    $actions[] = [
        'url' => "$baseurl/SharingGroups/delete/$SharingGroupId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroups/deleteSelection/$SharingGroupId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete SharingGroup'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>