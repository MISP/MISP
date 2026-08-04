<?php
$id     = h($data['AuthKey']['id']);
$ownerId = $data['User']['id'] ?? null;
$canEdit = !empty($isSiteAdmin)
    || !empty($me['Role']['perm_admin'])
    || (isset($me['id']) && $me['id'] == $ownerId);

$actions = [];

if ($canEdit) {
    $actions[] = [
        'url'     => "$baseurl/auth_keys/edit/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/auth_keys/edit/$id');",
        'icon'    => 'fas fa-pen-to-square',
        'label'   => __('Edit auth key'),
    ];
    $actions[] = [
        'url'     => "$baseurl/auth_keys/deleteSelection/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/auth_keys/deleteSelection/$id', 'sm');",
        'icon'    => 'fas fa-trash',
        'label'   => __('Delete auth key'),
        'danger'  => true,
    ];
}

$actions[] = [
    'url'   => "$baseurl/auth_keys/index" . ($ownerId ? '/' . h($ownerId) : ''),
    'icon'  => 'fas fa-list',
    'label' => __('Back to auth keys'),
];

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions,
]);
