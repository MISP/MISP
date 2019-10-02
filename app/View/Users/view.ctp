<?php
    $table_data = array();
    $table_data[] = array('key' => __('Id'), 'value' => $user['User']['id']);
    $table_data[] = array('key' => __('Email'), 'value' => $user['User']['email']);
    $table_data[] = array('key' => __('Organisation'), 'value' => $user['Organisation']['name']);
    $table_data[] = array('key' => __('Role'), 'html' => $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])));
    $table_data[] = array('key' => __('Autoalert'), 'boolean' => $user['User']['autoalert']);
    $table_data[] = array('key' => __('Contactalert'), 'boolean' => $user['User']['contactalert']);
    $authkey_data = sprintf(
        '<a onclick="requestAPIAccess();" style="cursor:pointer;"></a>',
        __('Request API access')
    );
    if ($user['Role']['perm_auth']) {
        $authkey_data = sprintf(
            '<span class="quickSelect">%s</span>%s',
            h($user['User']['authkey']),
            (Configure::read('MISP.disableUserSelfManagement') && !$isAdmin) ? '' :
                sprintf(
                    ' (%s)',
                    $this->Html->link(__('reset'), array('controller' => 'users', 'action' => 'resetauthkey', $user['User']['id']))
                )
        );
    }
    $table_data[] = array(
        'key' => __('Authkey'),
        'html' => $authkey_data
    );
    $table_data[] = array('key' => __('NIDS Start SID'), 'value' => $user['User']['nids_sid']);
    $table_data[] = array('key' => __('Terms accepted'), 'boolean' => $user['User']['termsaccepted']);
    $table_data[] = array(
        'key' => __('GnuPG key'),
        'element' => 'genericElements/key',
        'element_params' => array('key' => $user['User']['gpgkey']),
    );
    if (!empty($user['User']['gpgkey'])) {
        $table_data[] = array(
            'key' => __('GnuPG fingerprint'),
            'class_value' => "quickSelect bold " . $user['User']['gpgkey'] ? 'green' : 'bold red',
            'html' => $user['User']['fingerprint'] ? chunk_split(h($user['User']['fingerprint']), 4, ' ') : 'N/A'
        );
        $table_data[] = array(
            'key' => __('GnuPG status'),
            'class_value' => "bold" . (empty($user['User']['pgp_status']) || $user['User']['pgp_status'] != 'OK') ? 'red': 'green',
            'html' => !empty($user['User']['pgp_status']) ? h($user['User']['pgp_status']) : 'N/A'
        );
    }
    if (Configure::read('SMIME.enabled')) {
        $table_data[] = array(
            'key' => __('S/MIME Public certificate'),
            'element' => 'genericElements/key',
            'element_params' => array('key' => $user['User']['certif_public']),
        );
    }
    echo sprintf(
        '<div class="users view"><div class="row-fluid"><div class="span8" style="margin:0px;">%s</div></div>%s</div>%s',
        sprintf(
            '<h2>%s</h2>%s',
            __('User'),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        sprintf(
            '<a href="%s" class="btn btn-inverse" download>%s</a>',
            $baseurl . '/users/view/me.json',
            __('Download user profile for data portability')
        ),
        $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'))
    );
?>
