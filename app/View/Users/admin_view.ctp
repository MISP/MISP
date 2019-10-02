<?php
$buttonAddStatus = $isAclAdd ? 'button_on':'button_off';
$mayModify = ($isSiteAdmin || ($isAdmin && ($user['User']['org_id'] == $me['org_id'])));
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
    $table_data = array();
    $table_data[] = array('key' => __('Id'), 'value' => $user['User']['id']);
    $table_data[] = array(
        'key' => __('Email'),
        'html' => sprintf(
            '%s <a class="icon-envelope" href="%s/admin/users/quickEmail/%s"></a>',
            h($user['User']['email']),
            $baseurl,
            h($user['User']['id'])
        )
    );
    $table_data[] = array(
        'key' => __('Organisation'),
        'html' => sprintf(
            '<a href="%s/organisations/view/%s">%s</a>',
            $baseurl,
            h($user['Organisation']['id']),
            h($user['Organisation']['name'])
        )
    );
    $table_data[] = array('key' => __('Role'), 'html' => $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])));
    $table_data[] = array('key' => __('Autoalert'), 'boolean' => $user['User']['autoalert']);
    $table_data[] = array('key' => __('Contactalert'), 'boolean' => $user['User']['contactalert']);
    $authkey_data = sprintf(
        '<a onclick="requestAPIAccess();" style="cursor:pointer;"></a>',
        __('Request API access')
    );
    $authkey_data = sprintf(
        '<span class="quickSelect">%s</span>%s',
        h($user['User']['authkey']),
        sprintf(
            ' (%s)',
            $this->Html->link(__('reset'), array('controller' => 'users', 'action' => 'resetauthkey', $user['User']['id']))
        )
    );
    $table_data[] = array(
        'key' => __('Authkey'),
        'html' => $authkey_data
    );
    $table_data[] = array('key' => __('Invited By'), 'value' => $user2['User']['email']);
    $org_admin_data = array();
    foreach ($user['User']['orgAdmins'] as $orgAdminId => $orgAdminEmail) {
        $org_admin_data[] = sprintf(
            '<a href="%s/admin/users/view/%s">%s</a><a class="icon-envelope" href="%s/admin/users/quickEmail/%s"></a><br />',
            $baseurl,
            h($orgAdminId),
            h($orgAdminEmail),
            $baseurl,
            h($orgAdminId)
        );
    }
    $table_data[] = array('key' => __('Org_admin'), 'html' => implode('<br />', $org_admin_data));
    $table_data[] = array('key' => __('NIDS Start SID'), 'value' => $user['User']['nids_sid']);
    $table_data[] = array('key' => __('Terms accepted'), 'boolean' => $user['User']['termsaccepted']);
    $table_data[] = array('key' => __('Password change'), 'boolean' => $user['User']['change_pw']);
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
    $table_data[] = array('key' => __('Newsread'), 'html' => $user['User']['newsread'] ? date('Y/m/d H:i:s', h($user['User']['newsread'])) : __('N/A'));
    $table_data[] = array(
        'key' => __('Disabled'),
        'class' => empty($user['User']['disabled']) ? '' : 'background-red',
        'boolean' => $user['User']['disabled']
    );
    echo $this->element('genericElements/assetLoader', array(
        'css' => array('vis', 'distribution-graph'),
        'js' => array('vis', 'network-distribution-graph')
    ));
    echo sprintf(
        '<div class="users view row-fluid"><div class="span8" style="margin:0px;">%s%s</div>%s</div>%s',
        sprintf(
            '<h2>%s</h2>%s',
            __('User'),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        sprintf(
            '<br /><a href="%s" class="btn btn-inverse" download>%s</a>',
            sprintf(
                '%s/users/view/%s.json',
                $baseurl,
                h($user['User']['id'])
            ),
            __('Download user profile for data portability')
        ),
        '<div id="userEvents"></div>',
        $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'viewUser'))
    );
?>
<script type="text/javascript">
    $(document).ready(function () {
        $.ajax({
            url: '<?php echo $baseurl . "/events/index/searchemail:" . urlencode(h($user['User']['email'])); ?>',
            type:'GET',
            beforeSend: function (XMLHttpRequest) {
                $(".loading").show();
            },
            error: function(){
                $('#userEvents').html(__('An error has occurred, please reload the page.'));
            },
            success: function(response){
                $('#userEvents').html(response);
            },
            complete: function() {
                $(".loading").hide();
            }
        });
    });
</script>
