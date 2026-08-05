<?php
$id = $data['id'];
$galaxyId = $data['galaxy_id'];
$uuid = $data['uuid'];
$isDefault = !empty($data['default']);
$isPublished = !empty($data['published']);
$isDeleted = !empty($data['deleted']);
$isEditor = !empty($me['Role']['perm_galaxy_editor']);

$canEdit = !$isDefault && ($isSiteAdmin || ($isEditor && $data['org_id'] == $me['org_id']));
$canDelete = $isSiteAdmin || ($isEditor && $data['org_id'] == $me['org_id']);
$canPublish = !$isDefault && !$isPublished
    && ($isSiteAdmin || ($isEditor && !empty($me['Role']['perm_publish']) && $data['orgc_id'] == $me['org_id']));
$canRestore = $isDeleted && ($isSiteAdmin || $data['orgc_id'] == $me['org_id']);

$actions = [];

if ($canEdit) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/edit/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/edit/$id');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Edit Cluster'),
    ];
}

if ($isEditor) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/add/$galaxyId/forkUuid:$uuid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/add/$galaxyId/forkUuid:" . h($uuid) . "');",
        'icon' => 'fas fa-code-branch',
        'label' => __('Fork Cluster'),
    ];
}

$actions[] = [
    'url' => "$baseurl/galaxies/viewGraph/$id",
    'icon' => 'fas fa-share-nodes',
    'label' => __('View correlation graph'),
];

if (!$isDefault) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/export_for_misp_galaxy/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/export_for_misp_galaxy/$id');",
        'icon' => 'fas fa-handshake',
        'label' => __('Contribute to misp-galaxy'),
    ];
}

if ($canPublish) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/publish/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/publish/$id', 'sm');",
        'icon' => 'fas fa-upload',
        'label' => __('Publish Cluster'),
        'success' => true,
    ];
}

if ($canRestore) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/restore/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/restore/$id', 'sm');",
        'icon' => 'fas fa-trash-arrow-up',
        'label' => __('Restore Cluster'),
        'success' => true,
    ];
}

if ($canDelete) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/delete/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/delete/$id', 'lg');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Cluster'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
