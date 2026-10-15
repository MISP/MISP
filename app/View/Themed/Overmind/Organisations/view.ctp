<?php
$this->set('headerIdentity', $org['Organisation'] ?? []);
$orgData = $org['Organisation'] ?? [];
$orgId   = $orgData['id'] ?? $id;

// ── PAGE HEADER ──────────────────────────────────────────────────

$this->set('headerTitle', $orgData['name'] ?? '');

// Creation and modification details are only shown to those who could see
// them before: site admins and the organisation's own admins.
$headerParts = [];
if (!empty($isSiteAdmin) || !empty($fullAccess)) {
    if (!empty($orgData['date_created'])) {
        $headerParts[] = '<span title="' . h(__('Created')) . '"><i class="fas fa-calendar-plus me-1 opacity-50"></i>'
            . $this->Time->time($orgData['date_created'])
            . (!empty($orgData['created_by_email'])
                ? ' <span class="opacity-75">' . h(__('by %s', $orgData['created_by_email'])) . '</span>'
                : '')
            . '</span>';
    }
    if (!empty($orgData['date_modified'])) {
        $headerParts[] = '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>'
            . $this->Time->time($orgData['date_modified']) . '</span>';
    }
}
$this->set('headerDescription', empty($headerParts)
    ? ''
    : '<span class="d-inline-flex align-items-center gap-3 flex-wrap">' . implode('', $headerParts) . '</span>');

// ── TABS ─────────────────────────────────────────────────────────
$tabs = [
    [
        'id' => 'general',
        'title' => __('General'),
        'icon' => 'fas fa-circle-info',
        'left' => [
            'Organisations/View/organisations_general',
            'Organisations/View/organisations_related',
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
