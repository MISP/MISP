<?php
$id = $data['id'];
$enabled = !empty($data['enabled']);

$canEdit = empty($data['default']) && (
    $isSiteAdmin
    || (!empty($me['Role']['perm_galaxy_editor']) && isset($data['org_id']) && $data['org_id'] == $me['org_id'])
);

$actions = [];

if ($canEdit) {
    $actions[] = [
        'url' => "$baseurl/galaxies/edit/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/edit/$id');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Edit Galaxy'),
    ];

    $actions[] = [
        'url' => "$baseurl/galaxy_clusters/add/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxy_clusters/add/$id');",
        'icon' => 'fas fa-circle-plus',
        'label' => __('Add Galaxy Cluster'),
    ];
}

$actions[] = [
    'url' => "$baseurl/galaxies/export/$id",
    'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/export/$id');",
    'icon' => 'fas fa-download',
    'label' => __('Export Galaxy Clusters'),
];

if ($isSiteAdmin) {
    if (!$enabled) {
        $actions[] = [
            'url' => "$baseurl/galaxies/enable/$id",
            'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/toggle/$id', 'sm');",
            'icon' => 'fas fa-play',
            'label' => __('Enable Galaxy'),
            'success' => true,
        ];
    } else {
        $actions[] = [
            'url' => "$baseurl/galaxies/disable/$id",
            'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/toggle/$id', 'sm');",
            'icon' => 'fas fa-stop',
            'label' => __('Disable Galaxy'),
            'warning' => true,
        ];
    }

    $actions[] = [
        'url' => "$baseurl/galaxies/deleteSelection/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/galaxies/deleteSelection/$id', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Galaxy'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
