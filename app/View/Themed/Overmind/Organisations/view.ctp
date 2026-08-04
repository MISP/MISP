<?php
$orgData = $org['Organisation'] ?? [];
$orgId   = $orgData['id'] ?? $id;
$local   = !empty($orgData['local']);

// ── PAGE HEADER ──────────────────────────────────────────────────

$logo = $this->OrgImg->getOrgLogoV2($orgData, 40, false);
$headerTitleHtml = '<span class="d-inline-flex align-items-center gap-2">'
    . $logo
    . '<span>' . h($orgData['name'] ?? '') . '</span>'
    . '<span class="badge align-middle ' . ($local ? 'text-bg-success' : 'text-bg-secondary') . '" '
        . 'style="font-size:.7rem;">' . ($local ? __('Local') : __('Remote')) . '</span>'
    . '</span>';
$this->set('headerTitleHtml', $headerTitleHtml);

$description = trim($orgData['description'] ?? '');
if ($description !== '') {
    $this->set('headerDescription', nl2br(h($description), false));
}

// ── TABS ─────────────────────────────────────────────────────────
$tabs = [
    [
        'id' => 'general',
        'title' => __('General'),
        'icon' => 'fas fa-circle-info',
        'left' => [
            'Organisations/View/organisations_general',
        ],
        'right' => [
            'Organisations/View/organisations_actions',
        ],
    ],
];

$canViewUsers = !empty($isSiteAdmin)
    || (!empty($me['Role']['perm_admin']) && isset($me['org_id']) && $me['org_id'] == $orgId);
if ($canViewUsers) {
    $tabs[] = [
        'id' => 'users',
        'title' => __('Users'),
        'icon' => 'fas fa-users',
        'left' => [
            ['ajax' => sprintf('%s/admin/users/index/searchorg:%s', $baseurl, h($orgId))],
        ],
    ];
}

// Events created by this organisation.
$tabs[] = [
    'id'    => 'events',
    'title' => __('Events'),
    'icon'  => 'misp-icon misp-icon-event misp-simple',
    'left'  => [
        ['ajax' => sprintf(
            '%s/events/index/searchorg:%s',
            $baseurl,
            urlencode(h($orgId))
        )],
    ],
];

// Sharing groups this organisation is a member of.
$tabs[] = [
    'id' => 'sharing_groups',
    'title' => __('Sharing groups'),
    'icon' => 'fas fa-share-nodes',
    'left' => [
        ['ajax' => sprintf('%s/sharing_groups/index/searchorg:%s', $baseurl, h($orgId))],
    ],
];

// Header action for Users tab
$headerActions = [];
if ($canViewUsers) {
    $headerActions[] = [
        'type' => 'modal',
        'tab' => 'users',
        'label' => __('Add user'),
        'icon' => 'plus',
        'url' => sprintf('%s/admin/users/add/organisation:%s', $baseurl, h($orgId)),
    ];
}
$this->set('headerActions', $headerActions);

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $org,
    'tabs' => $tabs,
]);
