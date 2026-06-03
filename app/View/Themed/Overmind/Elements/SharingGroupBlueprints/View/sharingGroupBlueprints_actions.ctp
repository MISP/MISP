<?php
$sharingGroupBlueprintId = h($data['SharingGroupBlueprint']['id']);

$actions = [];

if ($me['Role']['perm_sharing_group']) {
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/edit/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/edit/$sharingGroupBlueprintId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit SharingGroupBlueprint')
    ];
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/push/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/execute/$sharingGroupBlueprintId', 'sm');",
        'icon' => 'fas fa-recycle',
        'label' => __('(Re)generate sharing group based on blueprint')
    ];
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/push/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/encodeSyncRule/$sharingGroupBlueprintId', 'sm');",
        'icon' => 'fas fa-filter',
        'label' => __("Encode blueprint's contents as a sync rule")
    ];
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/delete/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/deleteSelection/$sharingGroupBlueprintId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete SharingGroupBlueprint'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>