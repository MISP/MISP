<?php

$notificationTypes = [
    'autoalert' => __('Event published notification'),
    'notification_daily' => __('Daily notifications'),
    'notification_weekly' => __('Weekly notifications'),
    'notification_monthly' => __('Monthly notifications'),
];

$notificationsHtml = '<table>';
foreach ($notificationTypes as $notificationType => $description) {
    $isEnabled = !empty($user['User'][$notificationType]);
    $boolean = sprintf(
        '<span class="%s">%s</span>',
            $isEnabled ? 'label label-success label-padding' : 'label label-important label-padding',
        $isEnabled ? __('Yes') : __('No'));
    $notificationsHtml .= '<tr><td>' . $description . '</td><td>' . $boolean . '</td>';
}
$notificationsHtml .= '</table>';

$tableData = [
    array('key' => __('ID'), 'value' => $user['User']['id']),
    array(
        'key' => __('Email'),
        'html' => h($user['User']['email']) . ($admin_view ? sprintf(
                ' <a class="fas fa-envelope" style="color: #333" href="%s/admin/users/quickEmail/%s" title="%s"></a>',
                $baseurl,
                h($user['User']['id']),
                __('Send email to user')
            ) : ''),
    ),
    array(
        'key' => __('Organisation'),
        'html' => $this->OrgImg->getNameWithImg($user),
    ),
    array(
        'key' => __('Role'),
        'html' => $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])),
    ),
];

if (empty(Configure::read('Security.otp_disabled'))) {
    $isTotp = isset($user['User']['totp']);
    $boolean = sprintf(
        '<span class="%s">%s</span>',
        $isTotp ? 'label label-success label-padding' : 'label label-important label-padding',
        $isTotp ? __('Yes') : __('No'));
    $totpHtml = $boolean;
    $totpHtml .= (!$isTotp && !$admin_view ? $this->Html->link(__('Generate'), array('action' => 'totp_new')) : '');
    $totpHtml .= ($isTotp && !$admin_view ? $this->Html->link(__('View paper tokens'), array('action' => 'hotp', $user['User']['id'])): '');

    if ($isAdmin && $isTotp) {
        $totpHtml .= sprintf(
            '<a href="#" onClick="openGenericModal(\'%s/users/totp_delete/%s\')">%s</a>',
            h($baseurl),
            h($user['User']['id']),
            __($isTotp && !$admin_view ? ' Delete' : 'Delete')
        );
    }

    $tableData[] = [
        'key' => __('TOTP'),
        'html' => $totpHtml
    ];
}

$tableData[] = array(
    'key' => __('Email notifications'),
    'html' => $notificationsHtml,
);
$tableData[] = array('key' => __('Contact alert enabled'), 'boolean' => $user['User']['contactalert']);

if (!$admin_view && !$user['Role']['perm_auth']) {
    $tableData[] = array(
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
    $tableData[] = array(
        'key' => __('Auth key'),
        'html' => $authkey_data
    );
}

if (Configure::read('Plugin.CustomAuth_enable') && !empty($user['User']['external_auth_key'])) {
    $header = Configure::read('Plugin.CustomAuth_header') ?: 'AUTHORIZATION';
    $tableData[] = array(
        'key' => __('Customauth header'),
        'html' => sprintf(
            '%s: <span class="green bold">%s</span>',
            h($header),
            h($user['User']['external_auth_key'])
        )
    );
}
$tableData[] = array(
    'key' => __('Invited By'),
    'html' => empty($invitedBy['User']['email']) ? 'N/A' : sprintf('<a href="%s/admin/users/view/%s">%s</a>', $baseurl, h($invitedBy['User']['id']), h($invitedBy['User']['email'])),
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
    $tableData[] = array('key' => __('Org admin'), 'html' => implode('<br>', $org_admin_data));
}
$tableData[] = array('key' => __('NIDS Start SID'), 'value' => $user['User']['nids_sid']);
if ($admin_view) {
    $tableData[] = array('key' => __('Terms accepted'), 'boolean' => $user['User']['termsaccepted']);
    $tableData[] = array('key' => __('Must change password'), 'boolean' => $user['User']['change_pw']);
}
if (!empty($user['User']['gpgkey'])) {
    $tableData[] = array(
        'key' => __('PGP key'),
        'element' => 'genericElements/key',
        'element_params' => array('key' => $user['User']['gpgkey']),
    );
    $tableData[] = array(
        'key' => __('PGP key fingerprint'),
        'value_class' => 'quickSelect',
        'value' => $user['User']['fingerprint'] ? chunk_split($user['User']['fingerprint'], 4, ' ') : 'N/A'
    );
    $tableData[] = array(
        'key' => __('PGP key status'),
        'value_class' => (empty($user['User']['pgp_status']) || $user['User']['pgp_status'] !== 'OK') ? 'red': '',
        'value' => !empty($user['User']['pgp_status']) ? $user['User']['pgp_status'] : 'N/A'
    );
} else {
    $tableData[] = array(
        'key' => __('PGP key'),
        'boolean' => false,
    );
}
if (Configure::read('SMIME.enabled')) {
    $tableData[] = array(
        'key' => __('S/MIME Public certificate'),
        'element' => 'genericElements/key',
        'element_params' => array('key' => $user['User']['certif_public']),
    );
}
$tableData[] = array(
    'key' => __('Created'),
    'html' => $user['User']['date_created'] ? $this->Time->time($user['User']['date_created']) : __('N/A')
);
$tableData[] = array(
    'key' => __('Last password change'),
    'html' => $user['User']['last_pw_change'] ? $this->Time->time($user['User']['last_pw_change']) : __('N/A')
);
if ($admin_view) {
    $tableData[] = array(
        'key' => __('News read at'),
        'html' => $user['User']['newsread'] ? $this->Time->time($user['User']['newsread']) : __('N/A')
    );
    $tableData[] = array(
        'key' => __('Disabled'),
        'class' => empty($user['User']['disabled']) ? '' : 'background-red',
        'boolean' => $user['User']['disabled']
    );
}
echo $this->element('genericElements/assetLoader', array(
    'css' => array('vis', 'distribution-graph'),
    'js' => array('vis', 'jquery-ui.min', 'network-distribution-graph')
));
if (Configure::read('MISP.log_new_audit')) {
    $searchHtml = sprintf(
        '&nbsp;<a href="%s" class="btn btn-inverse">%s</a>',
        sprintf(
            '%s/admin/audit_logs/index/model:User/model_id:%s',
            $baseurl,
            h($user['User']['id'])
        ),
        __('Review user logs')
    );
} else {
    $searchHtml = sprintf(
        '&nbsp;<form action="%s" method="post" style="display:inline;">%s%s%s</form>',
        $baseurl . '/admin/logs/search/search',
        '<input type="hidden" value="User" name="model" />',
        '<input type="hidden" value="' . h($user['User']['id']) . '" name="model_id" />',
        sprintf(
            '<input type="submit" value="%s" class="btn btn-inverse">',
            __('Review user logs')
        )
    );
}
echo sprintf(
    '<div class="users view"><div class="row-fluid"><div class="span8" style="margin:0px;">%s</div></div>%s%s%s<div style="margin-top:20px;">%s%s%s</div></div>',
    sprintf(
        '<h2>%s</h2>%s',
        __('User %s', h($user['User']['email'])),
        $this->element('genericElements/viewMetaTable', array('table_data' => $tableData))
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
    $searchHtml,
    sprintf(
        '&nbsp;<a href="%s" class="btn btn-inverse">%s</a>',
        sprintf(
            '%s/users/view_login_history/%s',
            $baseurl,
            h($user['User']['id'])
        ),
        __('Review user logins')
    ),
    $me['Role']['perm_auth'] ? $this->element('/genericElements/accordion', array('title' => __('Auth keys'), 'url' => '/auth_keys/index/' . h($user['User']['id']))) : '',
    $me['Role']['perm_site_admin'] ?
        $this->element(
            '/genericElements/accordion',
            [
                'title' => __('Benchmarks'),
                'url' => '/benchmarks/index/scope:user/average:1/aggregate:1/key:' . h($user['User']['id'])
            ]
        ) :
        '',
    $this->element('/genericElements/accordion', array('title' => 'Events', 'url' => '/events/index/searchemail:' . urlencode(h($user['User']['email']))))
);
$current_menu = [
    'admin_view' => ['menuList' => 'admin', 'menuItem' => 'viewUser'],
    'view' => ['menuList' => 'globalActions', 'menuItem' => 'view']
];
echo $this->element('/genericElements/SideMenu/side_menu', $current_menu[$admin_view ? 'admin_view' : 'view']);
