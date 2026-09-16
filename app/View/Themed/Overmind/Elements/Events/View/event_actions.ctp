<?php

$eventId = h($data['Event']['id']);
$eventUuid = h($data['Event']['uuid'] ?? '');
$isPublished = (bool)$data['Event']['published'];

$mayModify = $this->Acl->canModifyEvent($data);
$canPublish = $this->Acl->canPublishEvent($data);
$canEdit = $isSiteAdmin || $mayModify;

$modal = function ($url, $size = null) {
    return sprintf(
        "event.preventDefault(); openModal('%s'%s);",
        $url,
        $size === null ? '' : ", '" . $size . "'"
    );
};

$actions = [];

if ($canEdit) {
    $actions[] = ['divider' => true, 'label' => __('Content')];

    $actions[] = [
        'url' => "$baseurl/events/edit/$eventId",
        'onclick' => $modal("$baseurl/events/edit/$eventId"),
        'icon' => 'fas fa-pen',
        'label' => __('Edit Event')
    ];

    $actions[] = [
        'url' => "$baseurl/events/delete/$eventId",
        'onclick' => $modal("$baseurl/events/delete/$eventId", 'md'),
        'icon' => 'fas fa-trash',
        'label' => __('Delete Event'),
        'danger' => true
    ];

    $actions[] = [
        'url' => "$baseurl/attributes/add/$eventId",
        'onclick' => $modal("$baseurl/attributes/add/$eventId"),
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
        'tour' => 'action-add-attribute',
        'label' => __('Add Attribute')
    ];

    $actions[] = [
        'url' => "$baseurl/objects/add/$eventId",
        'onclick' => $modal("$baseurl/objects/add/$eventId"),
        'icon' => 'misp-icon misp-icon-object misp-simple',
        'label' => __('Add Object')
    ];

    $actions[] = [
        'url' => "$baseurl/attributes/add_attachment/$eventId",
        'onclick' => $modal("$baseurl/attributes/add_attachment/$eventId"),
        'icon' => 'fas fa-paperclip',
        'label' => __('Add Attachment')
    ];

    $actions[] = [
        'url' => "$baseurl/event_reports/add/$eventId",
        'onclick' => $modal("$baseurl/event_reports/add/$eventId"),
        'icon' => 'misp-icon misp-icon-report misp-simple',
        'label' => __('Add Event Report')
    ];

    $actions[] = ['divider' => true, 'label' => __('Import & enrichment')];

    $actions[] = [
        'url' => "$baseurl/events/populateFrom/$eventId",
        'onclick' => $modal("$baseurl/events/populateFrom/$eventId"),
        'icon' => 'fas fa-sign-in-alt',
        'tour' => 'action-populate-from',
        'label' => __('Populate from')
    ];

    $actions[] = [
        'url' => "$baseurl/events/merge/$eventId",
        'onclick' => $modal("$baseurl/events/merge/$eventId", 'md'),
        'icon' => 'fas fa-layer-group',
        'label' => __('Merge attributes from')
    ];

    if (Configure::read('Plugin.Enrichment_services_enable')) {
        $actions[] = [
            'url' => "$baseurl/events/enrichEvent/$eventId",
            'onclick' => $modal("$baseurl/events/enrichEvent/$eventId"),
            'icon' => 'fas fa-wand-magic-sparkles',
            'label' => __('Enrich Event')
        ];
    }
}

$actions[] = ['divider' => true, 'label' => __('Share')];

if (!$isPublished && ($isSiteAdmin || ($mayModify && $canPublish))) {
    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/publish/$eventId", 'md'),
        'icon' => 'fas fa-upload',
        'tour' => 'action-publish',
        'label' => __('Publish Event'),
        'success' => true
    ];
} else if ($isPublished && ($isSiteAdmin || ($mayModify && $canPublish))) {
    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/unpublish/$eventId", 'md'),
        'icon' => 'fas fa-eye-slash',
        'tour' => 'action-unpublish',
        'label' => __('Unpublish Event'),
        'warning' => true
    ];
}

if (!empty($data['Orgc']['local'])) {
    $actions[] = [
        'url' => "$baseurl/events/contact/$eventId",
        'onclick' => $modal("$baseurl/events/contact/$eventId", 'md'),
        'icon' => 'fas fa-envelope',
        'label' => __('Contact Reporter')
    ];
}

$actions[] = [
    'url' => "$baseurl/events/exportChoice/$eventId",
    'onclick' => $modal("$baseurl/events/exportChoice/$eventId", 'md'),
    'icon' => 'fas fa-download',
    'label' => __('Download as')
];






if ($isPublished && !empty($me['Role']['perm_sighting'])) {
    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/publishSightings/$eventId", 'md'),
        'icon' => 'fas fa-eye',
        'label' => __('Publish Sightings')
    ];
}


if (Configure::read('MISP.delegation')) {
    $pendingDelegation = empty($delegationRequest) ? null : $delegationRequest;

    if ($pendingDelegation === null) {
        $onlyMyOrg = (int)($data['Event']['distribution'] ?? -1) === 0;
        if ((Configure::read('MISP.unpublishedprivate') || $onlyMyOrg)
            && ($isSiteAdmin || !empty($isAclDelegate))
        ) {
            $actions[] = [
                'url' => "$baseurl/event_delegations/delegateEvent/$eventId",
                'onclick' => $modal("$baseurl/event_delegations/delegateEvent/$eventId"),
                'icon' => 'fas fa-handshake',
                'label' => __('Delegate Publishing')
            ];
        }
    } else {
        $delegationId = h($pendingDelegation['EventDelegation']['id']);
        $myOrg = $me['org_id'] ?? null;
        $isTarget = $myOrg !== null && $myOrg == $pendingDelegation['EventDelegation']['org_id'];
        $isRequester = $myOrg !== null && $myOrg == $pendingDelegation['EventDelegation']['requester_org_id'];

        if ($isSiteAdmin || (!empty($isAclPublish) && ($isTarget || $isRequester))) {
            if ($isSiteAdmin || (!empty($isAclPublish) && $isTarget)) {
                $actions[] = [
                    'url' => "$baseurl/event_delegations/acceptDelegation/$delegationId",
                    'onclick' => $modal("$baseurl/event_delegations/acceptDelegation/$delegationId", 'md'),
                    'icon' => 'fas fa-handshake',
                    'label' => __('Accept Delegation Request'),
                    'success' => true
                ];
            }
            $actions[] = [
                'url' => "$baseurl/event_delegations/deleteDelegation/$delegationId",
                'onclick' => $modal("$baseurl/event_delegations/deleteDelegation/$delegationId", 'md'),
                'icon' => 'fas fa-handshake-slash',
                'label' => __('Discard Delegation Request'),
                'warning' => true
            ];
        }
    }
}

if ($isSiteAdmin) {
    $actions[] = ['divider' => true, 'label' => __('Maintenance')];

    if (Configure::read('Plugin.Workflow_enable')) {
        $actions[] = [
            'url' => "",
            'onclick' => $modal("$baseurl/events/runWorkflow/$eventId"),
            'icon' => 'fas fa-diagram-project',
            'label' => __('Run Ad-Hoc Workflow')
        ];
    }

    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/recorrelateEvent/$eventId", 'md'),
        'icon' => 'fas fa-arrows-rotate',
        'label' => __('Recorrelate Event')
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
