<?php
$noticelistId = (int)$data['Noticelist']['id'];
$enabled = !empty($data['Noticelist']['enabled']);

$actions = [
    [
        'url' => "$baseurl/noticelists/preview_entries/$noticelistId",
        'icon' => 'fas fa-eye',
        'label' => __('Preview entries'),
        'short' => __('Preview'),
    ],
];

if ($this->Acl->canAccess('noticelists', $enabled ? 'massDisable' : 'massEnable')) {
    $toggleUrl = $baseurl . '/noticelists/' . ($enabled ? 'massDisable' : 'massEnable') . '/' . $noticelistId;
    $actions[] = [
        'url' => $toggleUrl,
        'onclick' => "event.preventDefault(); openModal('" . h($toggleUrl) . "', 'md');",
        'icon' => $enabled ? 'fas fa-stop' : 'fas fa-play',
        'label' => $enabled ? __('Disable Noticelist') : __('Enable Noticelist'),
        'short' => $enabled ? __('Disable') : __('Enable'),
        'warning' => $enabled,
        'success' => !$enabled,
    ];
}

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/noticelists/delete/$noticelistId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/noticelists/delete/$noticelistId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Noticelist'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions,
]);
