<?php
$bookmarkId = h($data['Bookmark']['id']);

$actions = [];
if (preg_match('#^https?://#i', (string)($data['Bookmark']['url'] ?? ''))) {
    $actions[] = [
        'url' => $data['Bookmark']['url'],
        'icon' => 'fas fa-arrow-up-right-from-square',
        'label' => __('Open bookmark'),
        'short' => __('Open'),
        'attributes' => ['target' => '_blank', 'rel' => 'noopener noreferrer'],
    ];
}
if (!empty($mayModify)) {
    $actions[] = [
        'url' => "$baseurl/bookmarks/edit/$bookmarkId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/bookmarks/edit/$bookmarkId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit bookmark'),
        'short' => __('Edit'),
    ];
    $actions[] = [
        'url' => "$baseurl/bookmarks/deleteSelection/$bookmarkId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/bookmarks/deleteSelection/$bookmarkId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete bookmark'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions,
]);
