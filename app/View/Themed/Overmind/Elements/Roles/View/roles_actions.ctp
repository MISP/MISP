<?php

$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$roleId = h($data['Role']['id'] ?? '');

$actions = [];

if ($isSiteAdmin && $roleId !== '') {
    $actions[] = [
        'url' => "$baseurl/admin/roles/edit/$roleId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/roles/edit/$roleId');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Edit role'),
    ];
    $actions[] = [
        'url' => "$baseurl/admin/roles/deleteSelection/$roleId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/roles/deleteSelection/$roleId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete role'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
