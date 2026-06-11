<?php

$eventId = h($data['Event']['id']);
$isPublished = (bool)$data['Event']['published'];

$mayModify = $this->Acl->canModifyEvent($data);
$canPublish = $this->Acl->canPublishEvent($data);

$actions = [];
if ($isSiteAdmin || $mayModify) {
    $actions[] = [
        'url' => "$baseurl/events/edit/$eventId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/events/edit/$eventId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Event')
    ];

    $actions[] = [
        'url' => "$baseurl/attributes/add/$eventId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/attributes/add/$eventId');",
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
        'label' => __('Add Attribute')
    ];

    $actions[] = [
        'url' => "$baseurl/objects/add/$eventId",
        'icon' => 'misp-icon misp-icon-object misp-simple',
        'label' => __('Add Object')
    ];

    $actions[] = [
        'url' => "$baseurl/event_reports/add/$eventId",
        'icon' => 'misp-icon misp-icon-report misp-simple',
        'label' => __('Add Event Report')
    ];

    $actions[] = [
        'url' => "#",
        'onclick' => "event.preventDefault();getPopup($eventId, events, importChoice)",
        'icon' => 'fas fa-sign-in-alt',
        'label' => __('Populate from')
    ];

    $actions[] = [
        'url' => "$baseurl/events/export/$eventId",
        'icon' => 'fas fa-sign-out-alt',
        'label' => __('Export as')
    ];
}

if (!$isPublished && ($isSiteAdmin || ($mayModify && $canPublish))) {
    $actions[] = [
        'url' => "",
        'onclick' => "event.preventDefault(); openModal('$baseurl/events/publish/$eventId', 'md');",
        'icon' => 'fas fa-upload',
        'label' => __('Publish Event'),
        'success' => true
    ];
} else if($isPublished && ($isSiteAdmin || ($mayModify && $canPublish))) {
    $actions[] = [
        'url' => "",
        'onclick' => "event.preventDefault(); openModal('$baseurl/events/unpublish/$eventId', 'md');",
        'icon' => 'fas fa-download',
        'label' => __('Unpublish Event'),
        'warning' => true
    ];
}

if ($isSiteAdmin || $mayModify) {
    $actions[] = [
        'url' => "$baseurl/events/delete/$eventId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/events/delete/$eventId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Event'),
        'danger' => true
    ];
}


echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>