<?php

$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$org = $data['Organisation'] ?? [];
$orgId = $org['id'] ?? null;

$actions = [];

if ($isSiteAdmin && $orgId !== null) {
    $actions[] = [
        'url'     => "$baseurl/admin/organisations/edit/$orgId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/organisations/edit/$orgId');",
        'icon'    => 'fas fa-pen-to-square',
        'label'   => __('Edit organisation'),
    ];
}

$actions[] = [
    'url'   => "$baseurl/organisations/view/$orgId.json",
    'icon'  => 'fas fa-download',
    'label' => __('Download organisation'),
];

if ($isSiteAdmin && $orgId !== null) {
    $actions[] = [
        'url'     => "$baseurl/admin/organisations/deleteSelection/$orgId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/organisations/deleteSelection/$orgId', 'sm');",
        'icon'    => 'fas fa-trash',
        'label'   => __('Delete organisation'),
        'danger'  => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions,
]);
