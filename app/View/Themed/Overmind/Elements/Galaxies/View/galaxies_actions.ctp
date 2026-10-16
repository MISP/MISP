<?php
$id = $data['id'];
$enabled = !empty($data['enabled']);

$actions = [];

if ($this->Acl->canModifyGalaxy($galaxy)) {
    $actions[] = [
        'url' => "$baseurl/galaxies/edit/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/edit/$id');",
        'icon' => 'fas fa-pen',
        'entity' => 'galaxy',
        'label' => __('Edit Galaxy'),
        'short' => __('Edit'),
    ];
}

if ($this->Acl->canAccess('galaxies', 'add')) {
    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/add/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/add/$id');",
        'icon' => 'misp-icon misp-icon-galaxy misp-simple',
        'entity' => 'galaxy',
        'add' => true,
        'label' => __('Add Galaxy Cluster'),
        'short' => __('Add cluster'),
    ];
}

$actions[] = [
    'url' => "$baseurl/galaxies/export/$id",
    'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/export/$id');",
    'icon' => 'fas fa-download',
    'label' => __('Export Galaxy Clusters'),
    'short' => __('Export'),
];

if ($isSiteAdmin) {
    if (!$enabled) {
        $actions[] = [
            'url' => "$baseurl/galaxies/enable/$id",
            'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/toggle/$id', 'md');",
            'icon' => 'fas fa-toggle-on',
            'entity' => 'galaxy',
            'label' => __('Enable Galaxy'),
            'short' => __('Enable'),
        ];
    } else {
        $actions[] = [
            'url' => "$baseurl/galaxies/disable/$id",
            'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/toggle/$id', 'md');",
            'icon' => 'fas fa-toggle-off',
            'entity' => 'galaxy',
            'label' => __('Disable Galaxy'),
            'short' => __('Disable'),
        ];
    }

    $actions[] = [
        'url' => "$baseurl/galaxies/deleteSelection/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/deleteSelection/$id', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Galaxy'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
