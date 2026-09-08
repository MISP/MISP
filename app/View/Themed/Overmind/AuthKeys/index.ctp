<?php
$seenIpsEnabled = !Configure::read('MISP.disable_seen_ips_authkeys');
$canModify = !empty($canCreateAuthkey);

// Show the User cloumn only if we are not viewing the main index
$showUserColumn = empty($user_id) && (!empty($me['Role']['perm_admin']) || !empty($me['Role']['perm_site_admin']));

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'AuthKey.id',
        'card_section' => 'selector',
    ],
    [
        'name' => 'ID',
        'sort' => 'AuthKey.id',
        'data_path' => 'AuthKey.id',
        'element' => 'id',
        'url' => $baseurl . '/auth_keys/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('User'),
        'sort' => 'User.email',
        'data_path' => 'User.email',
        'id_path' => 'User.id',
        'element' => 'user_link',
        'requirement' => $showUserColumn,
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Auth Key'),
        'data_path' => 'AuthKey',
        'element' => 'authkey',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Expiration'),
        'sort' => 'AuthKey.expiration',
        'data_path' => 'AuthKey.expiration',
        'element' => 'expiration',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Last used'),
        'data_path' => 'AuthKey.last_used',
        'element' => 'datetime',
        'empty' => __('Never'),
        'requirement' => !empty($keyUsageEnabled),
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Allowed IPs'),
        'data_path' => 'AuthKey.allowed_ips',
        'element' => 'ip_list',
        'empty' => __('Any'),
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
];

if ($seenIpsEnabled) {
    $fields[] = [
        'name' => __('Seen IPs'),
        'data_path' => 'AuthKey.unique_ips',
        'element' => 'ip_list',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ];
}

$rowActions = [
    [
        'type' => 'navigate',
        'label' => __('View'),
        'icon' => 'eye',
        'url' => $baseurl . '/auth_keys/view/%id%',
    ],
    [
        'type' => 'modal',
        'label' => __('Edit'),
        'icon' => 'pen-to-square',
        'url' => $baseurl . '/auth_keys/edit/%id%',
        'requirement' => $canModify,
    ],
    [
        // Revoking expires the key on the spot. If it is
        // already expired, the action is hidden.
        'type' => 'modal',
        'label' => __('Revoke'),
        'icon' => 'ban',
        'class' => 'text-warning-emphasis',
        'size' => 'md',
        'url' => $baseurl . '/auth_keys/revoke/%id%',
        'requirement' => function ($row) use ($canModify) {
            if (!$canModify) {
                return false;
            }
            $expiration = (int)(Hash::get($row, 'AuthKey.expiration') ?? 0);
            return $expiration === 0 || $expiration > time();
        },
    ],
    [
        'type' => 'divider',
        'requirement' => $canModify,
    ],
    [
        'type' => 'modal',
        'label' => __('Delete'),
        'icon' => 'trash',
        'class' => 'text-danger',
        'url' => $baseurl . '/auth_keys/deleteSelection/%id%',
        'requirement' => $canModify,
    ],
];
$fields[] = [
    'name' => __('Actions'),
    'element' => 'row_actions',
    'data_path' => 'AuthKey.id',
    'card_section' => 'extra',
    'display_in' => ['table', 'card'],
    'actions' => $rowActions,
];

// Filter bar: quick search
$filterChildren = [];
$filterChildren[] = [
    'type' => 'search',
    'placeholder' => __('Search auth keys'),
    'name' => 'quickFilter',
    'mode' => 'quickFilter',
];
?>

<?php if (empty($advancedEnabled)): ?>
    <div class="alert alert-warning">
        <i class="fas fa-triangle-exclamation me-1"></i>
        <?= __('Advanced auth keys are not enabled.') ?>
    </div>
<?php endif; ?>

<?php
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'AuthKey.id',
            'row_dblclick_url' => $baseurl . '/auth_keys/view/%id%',
            'filter_bar' => [
                'children' => $filterChildren,
                'delete' => $canModify ? '/deleteSelection' : null,
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/auth_keys',
]);
?>
