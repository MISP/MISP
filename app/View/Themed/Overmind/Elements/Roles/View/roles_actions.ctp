<?php

$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$roleId = h($data['Role']['id'] ?? '');

$actions = [];

if ($isSiteAdmin && $roleId !== '') {
    $actions[] = [
        'url' => "$baseurl/admin/roles/edit/$roleId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/roles/edit/$roleId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit role'),
        'short' => __('Edit'),
    ];
    $actions[] = [
        'url' => "$baseurl/admin/roles/deleteSelection/$roleId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/roles/deleteSelection/$roleId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete role'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
