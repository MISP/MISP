<?php
$communityId = h($data['id']);

$actions = [];

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/communities/requestAccess/$communityId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/communities/requestAccess/$communityId');",
        'icon' => 'fas fa-hand-holding-hand',
        'label' => __('Request Access'),
        'short' => __('Request')
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>