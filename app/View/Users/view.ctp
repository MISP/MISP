<?php
    $table_data = array();
    $table_data[] = array('key' => __('ID'), 'value' => $user['User']['id']);
    $table_data[] = array(
        'key' => __('Email'),
        'html' => h($user['User']['email']) . ($admin_view ? sprintf(
            ' <a class="fas fa-envelope" style="color: #333" href="%s/admin/users/quickEmail/%s" title="%s"></a>',
            $baseurl,
            h($user['User']['id']),
            __('Send email to user')
        ) : ''),
    );
    $table_data[] = array(
        'key' => __('Organisation'),
        'html' => $this->OrgImg->getNameWithImg($user),
    );
    $table_data[] = array('key' => __('Role'), 'html' => $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])));
    $table_data[] = array('key' => __('Event alert enabled'), 'boolean' => $user['User']['autoalert']);
    $table_data[] = array('key' => __('Contact alert enabled'), 'boolean' => $user['User']['contactalert']);

    if (!$admin_view && !$user['Role']['perm_auth']) {
        $table_data[] = array(
            'key' => __('Auth key'),
            'html' => sprintf('<a onclick="requestAPIAccess();" class="useCursorPointer">%s</a>', __('Request API access')),
        );
    }

    if (empty(Configure::read('Security.advanced_authkeys')) && $user['Role']['perm_auth']) {
        $authkey_data = sprintf(
            '<span class="privacy-value quickSelect authkey" data-hidden-value="%s">****************************************</span>&nbsp;<i class="privacy-toggle fas fa-eye useCursorPointer" title="%s"></i>%s',
            h($user['User']['authkey']),
            __('Reveal hidden value'),
            sprintf(
                ' (%s)',
                $this->Form->postLink(__('reset'), array('action' => 'resetauthkey', $user['User']['id']))
            )
        );
        $table_data[] = array(
            'key' => __('Auth key'),
            'html' => $authkey_data
        );
    }

    if (Configure::read('Plugin.CustomAuth_enable') && !empty($user['User']['external_auth_key'])) {
        $header = Configure::read('Plugin.CustomAuth_header') ?: 'Authorization';
        $table_data[] = array(
            'key' => __('Customauth header'),
            'html' => sprintf(
                '%s: <span class="green bold">%s</span>',
                h($header),
                h($user['User']['external_auth_key'])
            )
        );
    }
    $table_data[] = array(
        'key' => __('Invited By'),
        'html' => empty($user2['User']['email']) ? 'N/A' : sprintf('<a href="%s/admin/users/view/%s">%s</a>', $baseurl, h($user2['User']['id']), h($user2['User']['email'])),
    );
    $org_admin_data = array();
    if ($admin_view) {
        foreach ($user['User']['orgAdmins'] as $orgAdminId => $orgAdminEmail) {
            $org_admin_data[] = sprintf(
                '<a href="%s/admin/users/view/%s">%s</a> <a class="fas fa-envelope" style="color: #333" href="%s/admin/users/quickEmail/%s" title="%s"></a>',
                $baseurl,
                h($orgAdminId),
                h($orgAdminEmail),
                $baseurl,
                h($orgAdminId),
                __('Send email to user')
            );
        }
        $table_data[] = array('key' => __('Org admin'), 'html' => implode('<br>', $org_admin_data));
    }
    $table_data[] = array('key' => __('NIDS Start SID'), 'value' => $user['User']['nids_sid']);
    if ($admin_view) {
        $table_data[] = array('key' => __('Terms accepted'), 'boolean' => $user['User']['termsaccepted']);
        $table_data[] = array('key' => __('Must change password'), 'boolean' => $user['User']['change_pw']);
    }
    $table_data[] = array(
        'key' => __('PGP key'),
        'element' => 'genericElements/key',
        'element_params' => array('key' => $user['User']['gpgkey']),
    );
    if (!empty($user['User']['gpgkey'])) {
        $table_data[] = array(
            'key' => __('PGP key fingerprint'),
            'class_value' => "quickSelect bold " . $user['User']['gpgkey'] ? 'green' : 'bold red',
            'value' => $user['User']['fingerprint'] ? chunk_split($user['User']['fingerprint'], 4, ' ') : 'N/A'
        );
        $table_data[] = array(
            'key' => __('PGP key status'),
            'class_value' => "bold" . (empty($user['User']['pgp_status']) || $user['User']['pgp_status'] != 'OK') ? 'red': 'green',
            'value' => !empty($user['User']['pgp_status']) ? $user['User']['pgp_status'] : 'N/A'
        );
    }
    if (Configure::read('SMIME.enabled')) {
        $table_data[] = array(
            'key' => __('S/MIME Public certificate'),
            'element' => 'genericElements/key',
            'element_params' => array('key' => $user['User']['certif_public']),
        );
    }
    $table_data[] = array(
        'key' => __('Created'),
        'value' => $user['User']['date_created'] ? date('Y-m-d H:i:s', $user['User']['date_created']) : __('N/A')
    );
    if ($admin_view) {
        $table_data[] = array(
            'key' => __('News read at'),
            'value' => $user['User']['newsread'] ? date('Y-m-d H:i:s', $user['User']['newsread']) : __('N/A')
        );
        $table_data[] = array(
            'key' => __('Disabled'),
            'class' => empty($user['User']['disabled']) ? '' : 'background-red',
            'boolean' => $user['User']['disabled']
        );
    }
    echo $this->element('genericElements/assetLoader', array(
        'css' => array('vis', 'distribution-graph'),
        'js' => array('vis', 'network-distribution-graph')
    ));
    echo sprintf(
        '<div class="users view"><div class="row-fluid"><div class="span8" style="margin:0px;">%s</div></div>%s<div style="margin-top:20px;">%s%s</div></div>',
        sprintf(
            '<h2>%s</h2>%s',
            __('User %s', h($user['User']['email'])),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        sprintf(
            '<br><a href="%s" class="btn btn-inverse" download>%s</a>',
            sprintf(
                '%s/users/view/%s.json',
                $baseurl,
                h($user['User']['id'])
            ),
            __('Download user profile for data portability')
        ),
        $me['Role']['perm_auth'] ? $this->element('/genericElements/accordion', array('title' => __('Auth keys'), 'url' => '/auth_keys/index/' . h($user['User']['id']))) : '',
        $this->element('/genericElements/accordion', array('title' => 'Events', 'url' => '/events/index/searchemail:' . urlencode(h($user['User']['email']))))
    );
    $current_menu = [
        'admin_view' => ['menuList' => 'admin', 'menuItem' => 'viewUser'],
        'view' => ['menuList' => 'globalActions', 'menuItem' => 'view']
    ];
    echo $this->element('/genericElements/SideMenu/side_menu', $current_menu[$admin_view ? 'admin_view' : 'view']);
