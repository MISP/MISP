<?php
$cerebrateId = h($data['Cerebrate']['id']);

$actions = [];

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/cerebrates/edit/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/edit/$cerebrateId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Cerebrate')
    ];
    $actions[] = [
        'url' => "$baseurl/cerebrates/pull_orgs/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/pull_orgs/$cerebrateId', 'sm');",
        'icon' => 'fas fa-arrow-circle-down',
        'label' => __('Sync organisation information')
    ];
    $actions[] = [
        'url' => "$baseurl/cerebrates/pull_sgs/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/pull_sgs/$cerebrateId', 'sm');",
        'icon' => 'fas fa-arrow-circle-down',
        'label' => __('Sync sharing group information')
    ];
    $actions[] = [
        'url' => "$baseurl/cerebrates/delete/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/deleteSelection/$cerebrateId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Cerebrate'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>