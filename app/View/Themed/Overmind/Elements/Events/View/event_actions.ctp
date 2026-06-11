<?php

$eventId = h($data['Event']['id']);
$isPublished = (bool)$data['Event']['published'];

$mayModify = $this->Acl->canModifyEvent($data);
$canPublish = $this->Acl->canPublishEvent($data);

$actions = [
    [
        'url' => "$baseurl/events/edit/$eventId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/events/edit/$eventId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Event')
    ],
    [
        'url' => "$baseurl/attributes/add/$eventId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/attributes/add/$eventId');",
        'icon' => 'fas fa-inbox',
        'label' => __('Add Attribute')
    ],
    [
        'url' => "$baseurl/objects/add/$eventId",
        'icon' => 'fas fa-cube',
        'label' => __('Add Object')
    ],
    [
        'url' => "$baseurl/event_reports/add/$eventId",
        'icon' => 'fas fa-file-alt',
        'label' => __('Add Event Report')
    ],
    [
        'url' => "#",
        'onclick' => "event.preventDefault();getPopup($eventId, events, importChoice)",
        'icon' => 'fas fa-sign-in-alt',
        'label' => __('Populate from')
    ],
    [
        'url' => "$baseurl/events/export/$eventId",
        'icon' => 'fas fa-sign-out-alt',
        'label' => __('Export as')
    ]
];

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