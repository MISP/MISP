<?php
$communityId = h($data['id']);

$actions = [];

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/communities/requestAccess/$communityId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/communities/requestAccess/$communityId');",
        'icon' => 'fas fa-hand-holding-hand',
        'label' => __('Request Access')
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>