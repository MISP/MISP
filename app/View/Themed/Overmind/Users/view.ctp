<?php
    $uid   = $user['User']['id'];
    $email = $user['User']['email'];
    $isOwnPermAuth  = !empty($me['Role']['perm_auth']);
    $isOwnSiteAdmin = !empty($me['Role']['perm_site_admin']);

    // Mirrors UserSetting::setSetting(): an org admin may not touch a site admin's settings
    $isSelf = (int)$me['id'] === (int)$uid;
    $canManageSettings = $isOwnSiteAdmin
        || (!empty($me['Role']['perm_admin'])
            && (int)$me['org_id'] === (int)$user['User']['org_id']
            && empty($user['Role']['perm_site_admin']))
        || ($isSelf && empty(Configure::read('MISP.disableUserSelfManagement')));

    $this->set('headerTitle', h($this->UserName->convertEmailToName($email)));

    $tabs = [
        [
            'id'    => 'general',
            'title' => __('General'),
            'icon'  => 'fas fa-circle-info',

            'left'  => [
                'Users/View/users_general',
            ],
            'right' => [
                'Users/View/users_actions',
            ],
        ],
        [
            'id'    => 'settings',
            'title' => __('Settings'),
            'icon'  => 'fas fa-sliders',
            'left'  => [
                ['ajax' => sprintf('%s/user_settings/index/user_id:%s', $baseurl, h($uid))],
            ],
        ],
    ];

    // Auth keys
    if ($isOwnPermAuth) {
        $tabs[] = [
            'id'    => 'authkeys',
            'title' => __('Auth keys'),
            'icon'  => 'fas fa-key',
            'left'  => [
                ['ajax' => sprintf('%s/auth_keys/index/%s', $baseurl, h($uid))],
            ],
        ];
    }

    // Benchmarks
    if ($isOwnSiteAdmin) {
        $tabs[] = [
            'id'    => 'benchmarks',
            'title' => __('Benchmarks'),
            'icon'  => 'fas fa-gauge-high',
            'left'  => [
                ['ajax' => sprintf(
                    '%s/benchmarks/index/scope:user/average:1/key:%s',
                    $baseurl,
                    h($uid)
                )],
            ],
        ];
    }

    // Events created by this user
    $tabs[] = [
        'id'    => 'events',
        'title' => __('Events'),
        'icon'  => 'misp-icon misp-icon-event misp-simple',
        'left'  => [
            ['ajax' => sprintf(
                '%s/events/index/searchemail:%s',
                $baseurl,
                urlencode(h($email))
            )],
        ],
    ];

    $headerActions = [];
    if ($canManageSettings) {
        $headerActions[] = [
            'type' => 'modal',
            'tab' => 'settings',
            'label' => __('Add setting'),
            'icon' => 'plus',
            'url' => $baseurl . '/user_settings/setSetting/' . h($uid),
        ];
    }
    if ($isOwnPermAuth) {
        $headerActions[] = [
            'type' => 'modal',
            'tab' => 'authkeys',
            'label' => __('Add authentication key'),
            'icon' => 'plus',
            'url' => $baseurl . '/auth_keys/add/' . h($uid),
        ];
    }
    $this->set('headerActions', $headerActions);

    echo $this->element('genericElementsBS5/Layout/view_layout', [
        'data' => $user,
        'tabs' => $tabs,
    ]);
?>
