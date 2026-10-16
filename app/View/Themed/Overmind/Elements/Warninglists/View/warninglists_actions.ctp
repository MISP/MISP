<?php

$warninglistId = h($data['Warninglist']['id']);
$enabled = $data['Warninglist']['enabled'];
$default = $data['Warninglist']['default'];
$mayModify = $this->Acl->canModifyWarninglist($data);

$actions = [];

if (!$default && $mayModify) {
    $actions[] = [
        'url' => "$baseurl/warninglists/edit/$warninglistId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/warninglists/edit/$warninglistId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Warninglist'),
        'short' => __('Edit')
    ];
}

if ($isSiteAdmin) {
    if (!$enabled) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/warninglists/toggleEnable/$warninglistId",
            'id' => $warninglistId,
            'icon' => 'fas fa-toggle-on',
            'label' => __('Enable Warninglist'),
            'short' => __('Enable'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/warninglists/toggleEnable/$warninglistId",
            'id' => $warninglistId,
            'icon' => 'fas fa-toggle-off',
            'label' => __('Disable Warninglist'),
            'short' => __('Disable'),
            'class' => 'text-warning'
        ];
    }
}

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/warninglists/delete/$warninglistId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/warninglists/deleteSelection/$warninglistId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Warninglist'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>
