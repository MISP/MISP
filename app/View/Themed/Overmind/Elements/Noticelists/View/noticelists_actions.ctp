<?php
$noticelistId = (int)$data['Noticelist']['id'];
$enabled = !empty($data['Noticelist']['enabled']);

$actions = [];
if ($this->Acl->canAccess('noticelists', $enabled ? 'massDisable' : 'massEnable')) {
    $toggleUrl = $baseurl . '/noticelists/' . ($enabled ? 'massDisable' : 'massEnable') . '/' . $noticelistId;
    $actions[] = [
        'url' => $toggleUrl,
        'onclick' => "event.preventDefault(); openModal('" . h($toggleUrl) . "', 'md');",
        'icon' => $enabled ? 'fas fa-stop' : 'fas fa-play',
        'label' => $enabled ? __('Disable Noticelist') : __('Enable Noticelist'),
        'warning' => $enabled,
        'success' => !$enabled,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions,
]);
