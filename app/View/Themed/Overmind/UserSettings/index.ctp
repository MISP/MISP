<?php

$this->set('headerTitle', __('User settings'));
$this->set('headerDescription', __('Manage the individual user settings.'));
$this->set('headerActions', [
    [
        'type' => 'modal',
        'label' => __('Add setting'),
        'icon' => 'plus',
        'url' => $baseurl . '/user_settings/setSetting',
    ],
]);

$settingDescriptions = $settingDescriptions ?? [];
// Set when the index is the Settings tab of a user's profile: one user, no scope buttons
$scopedUserId = $scopedUserId ?? null;

// Internal settings are refused by setSetting() and deleteSelection() outright, so they get no action menu at all.
$settingIsManageable = function (array $row) {
    return !empty($row['UserSetting']['_canDelete']);
};

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'UserSetting.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'UserSetting.id',
        'data_path' => 'UserSetting.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('User'),
        'sort' => 'User.email',
        'element' => 'custom',
        'function' => function (array $row) {
            $email = $row['User']['email'] ?? '';
            if ($email === '') {
                return '<span class="text-muted">&mdash;</span>';
            }
            $roleBadge = $this->element('genericElementsBS5/IndexTable/Fields/role', [
                'row' => $row,
                'field' => ['data_path' => 'User.Role', 'icon_only' => true],
            ]);
            return '<span class="d-inline-flex align-items-center gap-2">'
                . $roleBadge
                . '<span class="fw-semibold">' . h($email) . '</span>'
                . '</span>';
        },
        'requirement' => empty($scopedUserId),
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'User.org_id',
        'data_path' => 'User.Organisation',
        'element' => 'organisation',
        'requirement' => empty($scopedUserId),
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Setting'),
        'sort' => 'UserSetting.setting',
        'element' => 'custom',
        'function' => function (array $row) use ($settingDescriptions) {
            $setting = $row['UserSetting']['setting'] ?? '';
            $description = $settingDescriptions[$setting] ?? '';
            $nameClass = 'font-monospace small text-primary text-nowrap';
            if ($description === '') {
                return '<span class="' . $nameClass . '">' . h($setting) . '</span>';
            }
            return '<span class="d-inline-flex align-items-center gap-2 rounded-1 focus-ring ' . $nameClass . '"'
                . ' tabindex="0" data-bs-toggle="tooltip" data-bs-placement="top"'
                . ' title="' . h($description) . '">'
                . '<span class="text-decoration-none link-underline-primary'
                . ' link-underline-opacity-50 link-offset-1">' . h($setting) . '</span>'
                . '<i class="fas fa-circle-info text-body-secondary" aria-hidden="true"></i>'
                . '</span>';
        },
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Value'),
        'element' => 'custom',
        'function' => function (array $row) {
            return $this->element('UserSettings/setting_value', [
                'value' => $row['UserSetting']['value'] ?? null,
            ]);
        },
        'card_section' => 'links',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Restricted to'),
        'data_path' => 'UserSetting.restricted',
        'element' => 'restricted_to',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'UserSetting.id',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/user_settings/setSetting/%user_id%/%setting%',
                'url_params_data_paths' => [
                    'user_id' => 'UserSetting.user_id',
                    'setting' => 'UserSetting.setting',
                ],
                'requirement' => $settingIsManageable,
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'size' => 'md',
                'url' => $baseurl . '/user_settings/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $settingIsManageable,
            ],
        ],
    ],
];

// Keep the active scope + search across pagination / sort links — the Paginator
// would otherwise drop these named params.
$paginatorUrl = [];
foreach (['user_id', 'quickFilter', 'setting'] as $namedParam) {
    if (isset($this->request->params['named'][$namedParam])) {
        $paginatorUrl[$namedParam] = $this->request->params['named'][$namedParam];
    }
}
?>

<?php
$filterChildren = [
    [
        'type' => 'search',
        'button' => __('Search'),
        'placeholder' => __('Search a setting'),
        'name'        => 'quickFilter',
        'mode'        => 'quickFilter',
    ],
];
if (empty($scopedUserId)) {
    $filterChildren[] = [
        'type' => 'button',
        'label' => __('My settings'),
        'icon' => 'misp-icon misp-icon-user1 misp-simple',
        'class' => 'btn btn-primary',
        'url' => $baseurl . '/user_settings/index/user_id:me'
    ];
    $filterChildren[] = [
        'type' => 'button',
        'label' => __('Org settings'),
        'icon' => 'misp-icon misp-icon-organisation misp-simple',
        'class' => 'btn btn-primary',
        'url' => $baseurl . '/user_settings/index/user_id:org'
    ];
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxxxl' => 3],
            'paginatorOptions' => ['url' => $paginatorUrl],
            'filter_bar' => [
                'pull' => 'right',
                'children' => $filterChildren,
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
            'primary_id_path' => 'UserSetting.id',
        ]
    ],
    'item_url' => '/user_settings',
]);
