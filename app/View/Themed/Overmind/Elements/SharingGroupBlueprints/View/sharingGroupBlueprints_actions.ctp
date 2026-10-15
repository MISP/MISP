<?php
$sharingGroupBlueprintId = (int)$data['SharingGroupBlueprint']['id'];

$actions = [];

if ($me['Role']['perm_sharing_group']) {
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/edit/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/edit/$sharingGroupBlueprintId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit blueprint'),
        'short' => __('Edit')
    ];
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/execute/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/execute/$sharingGroupBlueprintId', 'md');",
        'icon' => 'fas fa-recycle',
        'label' => __('(Re)generate sharing group based on blueprint'),
        'short' => __('Regenerate')
    ];
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/encodeSyncRule/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/encodeSyncRule/$sharingGroupBlueprintId', 'md');",
        'icon' => 'fas fa-filter',
        'label' => __("Encode blueprint's contents as a sync rule"),
        'short' => __('Sync rule')
    ];
    $actions[] = [
        'url' => "$baseurl/SharingGroupBlueprints/delete/$sharingGroupBlueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/SharingGroupBlueprints/deleteSelection/$sharingGroupBlueprintId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete blueprint'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>