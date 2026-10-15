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
        'icon'    => 'fas fa-pen',
        'label'   => __('Edit auth key'),
        'short'   => __('Edit'),
    ];
    $actions[] = [
        'url'     => "$baseurl/auth_keys/deleteSelection/$id",
        'onclick' => "event.preventDefault(); openModal('$baseurl/auth_keys/deleteSelection/$id', 'md');",
        'icon'    => 'fas fa-trash',
        'label'   => __('Delete auth key'),
        'danger'  => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions,
]);
