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
            return '<span class="d-inline-flex align-items-center gap-2">'
                . '<i class="misp-icon misp-icon-user1 misp-simple text-muted"></i>'
                . '<span class="fw-semibold">' . h($email) . '</span>'
                . '</span>';
        },
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'User.org_id',
        'data_path' => 'User.Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Setting'),
        'sort' => 'UserSetting.setting',
        'element' => 'custom',
        'function' => function (array $row) {
            $setting = $row['UserSetting']['setting'] ?? '';
            return '<code class="text-primary">' . h($setting) . '</code>';
        },
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Value'),
        'data_path' => 'UserSetting.value',
        'element' => 'json',
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
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'size' => 'sm',
                'url' => $baseurl . '/user_settings/deleteSelection/%id%',
                'class' => 'text-danger',
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
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'paginatorOptions' => ['url' => $paginatorUrl],
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search a setting'),
                        'name'        => 'quickFilter',
                        'mode'        => 'quickFilter',
                    ],
                    [
                        'type' => 'button',
                        'label' => __('My settings'),
                        'icon' => 'misp-icon misp-icon-user1 misp-simple',
                        'class' => 'btn btn-primary',
                        'url' => $baseurl . '/user_settings/index/user_id:me'
                    ],
                    [
                        'type' => 'button',
                        'label' => __('Org settings'),
                        'icon' => 'misp-icon misp-icon-organisation misp-simple',
                        'class' => 'btn btn-primary',
                        'url' => $baseurl . '/user_settings/index/user_id:org'
                    ]
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
            'primary_id_path' => 'UserSetting.id',
        ]
    ],
    'item_url' => '/user_settings',
]);
