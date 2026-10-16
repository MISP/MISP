<?php
$cerebrateId = h($data['Cerebrate']['id']);

$actions = [];

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/cerebrates/edit/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/edit/$cerebrateId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Cerebrate'),
        'short' => __('Edit')
    ];
    $actions[] = [
        'url' => "$baseurl/cerebrates/pull_orgs/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/pull_orgs/$cerebrateId', 'md');",
        'icon' => 'fas fa-circle-arrow-down',
        'label' => __('Sync organisation information'),
        'short' => __('Sync orgs')
    ];
    $actions[] = [
        'url' => "$baseurl/cerebrates/pull_sgs/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/pull_sgs/$cerebrateId', 'md');",
        'icon' => 'fas fa-circle-arrow-down',
        'label' => __('Sync sharing group information'),
        'short' => __('Sync SGs')
    ];
    $actions[] = [
        'url' => "$baseurl/cerebrates/delete/$cerebrateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/cerebrates/deleteSelection/$cerebrateId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Cerebrate'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>