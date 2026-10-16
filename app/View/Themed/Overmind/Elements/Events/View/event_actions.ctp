<?php

$eventId = h($data['Event']['id']);
$eventUuid = h($data['Event']['uuid'] ?? '');
$isPublished = (bool)$data['Event']['published'];
$lastPublished = (int)($data['Event']['publish_timestamp'] ?? 0);
$hasPending = $lastPublished > 0 && (int)$data['Event']['timestamp'] > $lastPublished;

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
        'label' => __('Add Attribute'),
        'add' => true,
        'short' => __('Attribute'),
        'entity' => 'attribute'
    ];

    $actions[] = [
        'url' => "$baseurl/objects/add/$eventId",
        'onclick' => $modal("$baseurl/objects/add/$eventId"),
        'icon' => 'misp-icon misp-icon-object misp-simple',
        'tour' => 'action-add-object',
        'label' => __('Add Object'),
        'pinned' => true,
        'tileOrder' => 1,
        'add' => true,
        'short' => __('Object'),
        'entity' => 'object'
    ];

    $actions[] = [
        'url' => "$baseurl/attributes/add_attachment/$eventId",
        'onclick' => $modal("$baseurl/attributes/add_attachment/$eventId"),
        'icon' => 'fas fa-paperclip',
        'tour' => 'action-add-attachment',
        'label' => __('Add Attachment'),
        'pinned' => true,
        'tileOrder' => 2,
        'add' => true,
        'short' => __('Attach'),
        'entity' => 'attribute'
    ];

    $actions[] = [
        'url' => "$baseurl/event_reports/add/$eventId",
        'onclick' => $modal("$baseurl/event_reports/add/$eventId"),
        'icon' => 'misp-icon misp-icon-report misp-simple',
        'tour' => 'action-add-report',
        'label' => __('Add Event Report'),
        'pinned' => true,
        'tileOrder' => 3,
        'add' => true,
        'short' => __('Report'),
        'entity' => 'report'
    ];

    $actions[] = [
        'url' => "$baseurl/events/edit/$eventId",
        'onclick' => $modal("$baseurl/events/edit/$eventId"),
        'icon' => 'fas fa-pen',
        'tour' => 'action-edit-event',
        'label' => __('Edit Event'),
        'pinned' => true,
        'tileOrder' => 5,
        'short' => __('Edit'),
        'entity' => 'event'
    ];

    $actions[] = ['divider' => true, 'label' => __('Import & enrichment')];

    $actions[] = [
        'url' => "$baseurl/events/populateFrom/$eventId",
        'onclick' => $modal("$baseurl/events/populateFrom/$eventId"),
        'icon' => 'fas fa-sign-in-alt',
        'tour' => 'action-populate-from',
        'label' => __('Populate from'),
        'pinned' => true,
        'tileOrder' => 4,
        'short' => __('Populate'),
        'entity' => 'attribute'
    ];

    if (Configure::read('Plugin.AI_services_enable') && $this->Acl->canAccess('events', 'aiActions')) {
        $actions[] = [
            'url' => "$baseurl/events/aiActions/$eventId",
            'onclick' => $modal("$baseurl/events/aiActions/$eventId", 'md'),
            'icon' => 'fas fa-robot',
            'label' => __('AI actions'),
            'short' => __('AI'),
            'entity' => 'enrichment'
        ];
    }

    $actions[] = [
        'url' => "$baseurl/events/merge/$eventId",
        'onclick' => $modal("$baseurl/events/merge/$eventId", 'md'),
        'icon' => 'fas fa-layer-group',
        'label' => __('Merge attributes from'),
        'short' => __('Merge'),
        'entity' => 'attribute'
    ];

    if (Configure::read('Plugin.Enrichment_services_enable')) {
        $actions[] = [
            'url' => "$baseurl/events/enrichEvent/$eventId",
            'onclick' => $modal("$baseurl/events/enrichEvent/$eventId"),
            'icon' => 'fas fa-wand-magic-sparkles',
            'tour' => 'action-enrich',
            'label' => __('Enrich Event'),
            'short' => __('Enrich'),
            'entity' => 'enrichment'
        ];
    }

    $mayToggleCorrelation = !Configure::read('MISP.completely_disable_correlation')
        && ($isSiteAdmin || Configure::read('MISP.allow_disabling_correlation'));
    $mayProtect = (int)$me['org_id'] === (int)$data['Event']['orgc_id']
        && !empty($hostOrgUser) && empty($data['Event']['locked']);
    if ($mayToggleCorrelation || $mayProtect) {
        $actions[] = ['divider' => true, 'label' => __('Event settings')];
    }
    if ($mayToggleCorrelation) {
        $correlationOff = !empty($data['Event']['disable_correlation']);
        $actions[] = [
            'url' => "$baseurl/events/toggleCorrelation/$eventId",
            'onclick' => $modal("$baseurl/events/toggleCorrelation/$eventId", 'md'),
            'icon' => $correlationOff ? 'fas fa-link' : 'fas fa-unlink',
            'label' => $correlationOff ? __('Enable correlation') : __('Disable correlation'),
            'short' => __('Correlation'),
            'entity' => 'correlation'
        ];
    }
    if ($mayProtect) {
        $isProtected = !empty($data['Event']['protected']);
        $protectAction = $isProtected ? 'unprotect' : 'protect';
        $actions[] = [
            'url' => "$baseurl/events/$protectAction/$eventId",
            'onclick' => $modal("$baseurl/events/$protectAction/$eventId", 'md'),
            'icon' => $isProtected ? 'fas fa-unlock' : 'fas fa-shield-alt',
            'label' => $isProtected ? __('Remove protection') : __('Protect event'),
            'short' => $isProtected ? __('Unprotect') : __('Protect'),
            'entity' => 'event'
        ];
        if ($isProtected) {
            $actions[] = [
                'url' => "$baseurl/CryptographicKeys/add/Event/$eventId",
                'onclick' => $modal("$baseurl/CryptographicKeys/add/Event/$eventId"),
                'icon' => 'fas fa-key',
                'label' => __('Add signing key'),
                'short' => __('Signing key'),
                'entity' => 'event'
            ];
        }
    }
}

$actions[] = ['divider' => true, 'label' => __('Share')];

if ($this->Acl->canAccess('collectionElements', 'addElementToCollection')) {
    $actions[] = [
        'url' => "$baseurl/collectionElements/addElementToCollection/Event/$eventUuid",
        'onclick' => $modal("$baseurl/collectionElements/addElementToCollection/Event/$eventUuid", 'xl'),
        'icon' => 'fas fa-folder-plus',
        'label' => __('Add to collection'),
        'short' => __('Collection'),
        'entity' => 'collection',
    ];
}

if ($this->Acl->canAccess('analystGraphs', 'addNodes')) {
    $actions[] = [
        'url' => '#',
        'icon' => 'misp-icon misp-icon-analyst-graph misp-simple',
        'label' => __('Add to graph'),
        'short' => __('Graph'),
        'entity' => 'analystGraph',
        'attributes' => ['data-intel-graph-add' => json_encode([[
            'type' => 'Event', 'uuid' => $data['Event']['uuid'], 'label' => $data['Event']['info'],
        ]])],
    ];
}

$mayPublish = $isSiteAdmin || ($mayModify && $canPublish);
if ($mayPublish && (!$isPublished || $hasPending)) {
    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/publish/$eventId", 'md'),
        'icon' => 'fas fa-upload',
        'tour' => 'action-publish',
        'label' => __('Publish Event'),
        'primary' => true,
        'short' => __('Publish'),
        'success' => true
    ];
}
if ($mayPublish && $isPublished) {
    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/unpublish/$eventId", 'md'),
        'icon' => 'fas fa-eye-slash',
        'tour' => 'action-unpublish',
        'label' => __('Unpublish Event'),
        'primary' => !$hasPending,
        'short' => __('Unpublish'),
        'warning' => true
    ];
}

if (!empty($data['Orgc']['local'])) {
    $actions[] = [
        'url' => "$baseurl/events/contact/$eventId",
        'onclick' => $modal("$baseurl/events/contact/$eventId", 'md'),
        'icon' => 'fas fa-envelope',
        'label' => __('Contact Reporter'),
        'short' => __('Contact')
    ];
}

$actions[] = [
    'url' => "$baseurl/events/exportChoice/$eventId",
    'onclick' => $modal("$baseurl/events/exportChoice/$eventId", 'md'),
    'icon' => 'fas fa-download',
    'tour' => 'action-download',
    'label' => __('Download as'),
    'short' => __('Download')
];






if ($isPublished && !empty($me['Role']['perm_sighting'])) {
    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/publishSightings/$eventId", 'md'),
        'icon' => 'fas fa-eye',
        'label' => __('Publish Sightings'),
        'short' => __('Sightings'),
        'entity' => 'sighting'
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
                'label' => __('Delegate Publishing'),
                'short' => __('Delegate')
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
                    'short' => __('Accept'),
                    'success' => true
                ];
            }
            $actions[] = [
                'url' => "$baseurl/event_delegations/deleteDelegation/$delegationId",
                'onclick' => $modal("$baseurl/event_delegations/deleteDelegation/$delegationId", 'md'),
                'icon' => 'fas fa-handshake-slash',
                'label' => __('Discard Delegation Request'),
                'short' => __('Discard'),
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
            'label' => __('Run Ad-Hoc Workflow'),
            'short' => __('Workflow')
        ];
    }

    $actions[] = [
        'url' => "",
        'onclick' => $modal("$baseurl/events/recorrelateEvent/$eventId", 'md'),
        'icon' => 'fas fa-arrows-rotate',
        'label' => __('Recorrelate Event'),
        'short' => __('Recorrelate'),
        'entity' => 'correlation'
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions,
    'status' => [
        'published' => $isPublished,
        'readOnly' => !$canEdit,
        'pending' => $hasPending,
        'lastPublished' => $lastPublished,
    ],
    'maxTiles' => 5,
    'columns' => 5,
    'autoPin' => false,
]);
