<div class="users form">
<?php echo $this->Form->create('User', array('novalidate' => true));?>
    <fieldset>
        <legend><?php echo __('Admin Edit User'); ?></legend>
    <?php
        echo $this->Form->input('email', [
            'disabled' => !$canChangeLogin,
            'data-disabled-reason' => !$canChangePassword ? __('User login change is disabled on this instance') : '',
        ]);
    ?>
        <div class="clear"></div>
    <?php
        $password = true;
        if (Configure::read('Plugin.CustomAuth_enable')) {
            if (Configure::read('Plugin.CustomAuth_required')) {
                $password = false;
            } else {
                $userType = Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : 'External authentication';
                echo $this->Form->input('external_auth_required', array('type' => 'checkbox', 'label' => $userType . ' user'));
            }
            echo sprintf(
                '<div class="clear"></div><div %s>%s</div>',
                (
                    (
                        !empty(Configure::read('Plugin.CustomAuth_required')) &&
                        !empty(Configure::read('Plugin.CustomAuth_enable'))
                    ) ? '' : sprintf('id="externalAuthDiv"')
                ),
                $this->Form->input('external_auth_key', array('type' => 'text'))
            );
        }
    ?>
    <div class="clear"></div>
    <div id="passwordDivDiv" style="<?= (!empty(Configure::read('Plugin.CustomAuth_required')) && !empty(Configure::read('Plugin.CustomAuth_enable'))) ? 'display:none;' : ''?>">
        <?php
            echo $this->Form->input('enable_password', [
                'type' => 'checkbox',
                'label' => __('Set password'),
                'disabled' => !$canChangePassword,
                'data-disabled-reason' => !$canChangePassword ? __('User password change is disabled on this instance') : '',
            ]);
        ?>
        <div id="PasswordDiv">
            <div class="clear"></div>
            <?php
                $passwordPopover = '<span class="blue bold">' . __('Length') .'</span>: ' . h($length) . '<br>';
                $passwordPopover .= '<span class="blue bold">' . __('Complexity') .'</span>: ' . h($complexity);
                echo $this->Form->input('password', array(
                    'label' => __('Password') . ' <span id="PasswordPopover" data-content="' . h($passwordPopover) .'" class="fas fa-info-circle"></span>'
                ));
                echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
            ?>
        </div>
    </div>
    <div class="clear"></div>
    <?php
        if ($isSiteAdmin) {
            echo $this->Form->input('org_id', array(
                    'options' => $orgs,
                    'label' => __('Organisation'),
            ));
        }
        echo $this->Form->input('role_id', array(
            'label' => __('Role'),
            'div' => empty(Configure::read('Security.advanced_authkeys')) ? null : 'input clear'
        ));
        if (empty(Configure::read('Security.advanced_authkeys'))) {
            $authkeyLabel = __('Authkey') . ' <a class="useCursorPointer" onclick="$(\'#resetAuthKeyForm\').submit();">' . __('(Reset)') . '</a>';
            echo $this->Form->input('authkey', array('disabled' => true, 'div' => 'input clear', 'label' => $authkeyLabel));
        }
        echo $this->Form->input('nids_sid', ['label' => __('NIDS SID')]);
    ?>
        <div id="syncServers" class="hidden">
    <?php
            echo $this->Form->input('server_id', array('label' => __('Sync user for'), 'div' => 'clear', 'options' => $servers));
    ?>
        </div>
    <?php
        echo $this->Form->input('gpgkey', array('label' => __('PGP key'), 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => __('Paste the user\'s PGP key here or try to retrieve it from the CIRCL key server by clicking on "Fetch PGP key" below.')));
    ?>
        <div class="clear"><span role="button" tabindex="0" aria-label="<?php echo __('Fetch the user\'s PGP key');?>" onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;"><?php echo __('Fetch PGP key');?></span></div>
    <?php
        if (Configure::read('SMIME.enabled')) {
            echo $this->Form->input('certif_public', array('label' => __('S/MIME Public certificate (PEM format)'), 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => __('Paste the user\'s S/MIME public key in PEM format here.')));
        }
        echo '<div class="user-edit-checkboxes">';
        echo $this->Form->input('termsaccepted', array('type' => 'checkbox', 'label' => __('Terms accepted')));
        echo $this->Form->input('change_pw', [
            'type' => 'checkbox',
            'label' => __('User must change password'),
            'disabled' => !$canChangePassword,
            'data-disabled-reason' => !$canChangePassword ? __('User password change is disabled on this instance') : '',
        ]);
        echo $this->Form->input('autoalert', array('label' => __('Receive email alerts when events are published'), 'type' => 'checkbox'));
        echo $this->Form->input('contactalert', array('label' => __('Receive email alerts from "Contact reporter" requests'), 'type' => 'checkbox'));
        echo $this->Form->input('disabled', array('type' => 'checkbox', 'label' => __('Immediately disable this user account')));
        echo '</div>';
    ?>
    </fieldset>
    <div style="border-bottom: 1px solid #e5e5e5;width:100%;">&nbsp;</div>
    <div class="clear" style="margin-top:10px;">
<?php
    if (Configure::read('Security.require_password_confirmation')) {
        echo $this->Form->input('current_password', array('type' => 'password', 'div' => false, 'class' => 'input password required', 'label' => __('Confirm with your current password')));
    }
?>
    </div>
<?php
    echo $this->Form->button(__('Edit user'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
    echo $this->Form->create('User', array(
        'url' => array('controller' => 'users', 'action' => 'resetauthkey', $id),
        'id' => 'resetAuthKeyForm'
    ));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'editUser'));
?>

<script type="text/javascript">
    var syncRoles = <?php echo json_encode($syncRoles); ?>;
    $(function() {
        syncUserSelected();
        $('#UserRoleId').change(function() {
            syncUserSelected();
        });
        checkUserPasswordEnabled();
        checkUserExternalAuth();
        $('#UserEnablePassword').change(function() {
            checkUserPasswordEnabled();
        });
        $('#UserExternalAuthRequired').change(function() {
            checkUserExternalAuth();
        });
    });
</script>
