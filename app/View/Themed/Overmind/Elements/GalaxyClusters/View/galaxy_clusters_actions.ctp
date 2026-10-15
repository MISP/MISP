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
        'icon' => 'fas fa-pen',
        'entity' => 'galaxy',
        'label' => __('Edit Cluster'),
        'short' => __('Edit'),
    ];
}

if ($isEditor) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/add/$galaxyId/forkUuid:$uuid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/add/$galaxyId/forkUuid:" . h($uuid) . "');",
        'icon' => 'fas fa-code-branch',
        'entity' => 'galaxy',
        'label' => __('Fork Cluster'),
        'short' => __('Fork'),
    ];
}

$actions[] = [
    'url' => "$baseurl/galaxies/viewGraph/$id",
    'icon' => 'fas fa-share-nodes',
    'entity' => 'correlation',
    'label' => __('View correlation graph'),
    'short' => __('Correlations'),
];

if ($this->Acl->canAccess('analystGraphs', 'addNodes') && !$isDeleted) {
    $actions[] = [
        'url' => '#',
        'icon' => 'misp-icon misp-icon-analyst-graph misp-simple',
        'entity' => 'analystGraph',
        'label' => __('Add to graph'),
        'short' => __('Graph'),
        'attributes' => ['data-intel-graph-add' => json_encode([['type' => 'GalaxyCluster', 'uuid' => $uuid, 'label' => $data['value']]])],
    ];
}

if (!$isDefault) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/export_for_misp_galaxy/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/export_for_misp_galaxy/$id');",
        'icon' => 'fas fa-handshake',
        'label' => __('Contribute to misp-galaxy'),
        'short' => __('Contribute'),
    ];
}

if ($canPublish) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/publish/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/publish/$id', 'md');",
        'icon' => 'fas fa-upload',
        'primary' => true,
        'label' => __('Publish Cluster'),
        'short' => __('Publish'),
        'success' => true,
    ];
}

if ($canRestore) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/restore/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/restore/$id/origin:view', 'md');",
        'icon' => 'fas fa-trash-arrow-up',
        'entity' => 'galaxy',
        'label' => __('Restore Cluster'),
        'short' => __('Restore'),
    ];
}

if ($canDelete) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/delete/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/delete/$id/origin:view', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Cluster'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions,
    'status' => $isDefault ? [] : [
        'published' => $isPublished,
        'readOnly' => !$canEdit,
    ],
]);
