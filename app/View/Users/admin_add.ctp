<div class="users form">
<?php echo $this->Form->create('User', array('novalidate'=>true));?>
    <fieldset>
        <legend><?php echo __('Admin Add User'); ?></legend>
    <?php
        echo $this->Form->input('email');
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
            echo $this->Form->input('enable_password', array('type' => 'checkbox', 'label' => __('Set password')));
        ?>
        <div id="PasswordDiv">
            <div class="clear"></div>
            <?php
                $passwordPopover = '<span class="blue bold">' . __('Minimal length') . '</span>: ' . h($length) . '<br>';
                $passwordPopover .= '<span class="blue bold">' . __('Complexity') . '</span>: ' . h($complexity);
                echo $this->Form->input('password', array(
                    'label' => __('Password') . ' <span id="PasswordPopover" data-content="' . h($passwordPopover) . '" class="fas fa-info-circle"></span>'
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
                    'empty' => __('Choose organisation'),
            ));
        }
        $roleOptions = array(
            'label' => __('Role'),
            'div' => empty(Configure::read('Security.advanced_authkeys')) ? null : 'input clear'
        );
        // We need to make sure that the default role is actually available to the admin (for an org admin it might not be)
        if (!empty($default_role_id) && isset($roles[intval($default_role_id)])) {
            $roleOptions['default'] = $default_role_id;
        }
        echo $this->Form->input('role_id', $roleOptions);
        if (empty(Configure::read('Security.advanced_authkeys'))) {
            echo $this->Form->input('authkey', array('value' => $authkey, 'readonly' => 'readonly', 'div' => 'input clear'));
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
        <div class="clear"><span  role="button" tabindex="0" aria-label="<?php echo __('Fetch the user\'s PGP key');?>" onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;"><?php echo __('Fetch PGP key');?></span></div>
    <?php
        if (Configure::read('SMIME.enabled')) echo $this->Form->input('certif_public', array('label' => __('S/MIME Public certificate (PEM format)'), 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => __('Paste the user\'s S/MIME public key in PEM format here.')));
    ?>
    <div class="user-edit-checkboxes" style="margin-bottom: 1em">
    <?php
        $default_publish_alert = Configure::check('MISP.default_publish_alert') ? Configure::read('MISP.default_publish_alert') : true;
        echo $this->Form->input('autoalert', array(
            'label' => __('Receive email alerts when events are published'),
            'type' => 'checkbox',
            'checked' => isset($this->request->data['User']['autoalert']) ? $this->request->data['User']['autoalert'] : $default_publish_alert
        ));
        echo $this->Form->input('contactalert', array(
            'label' => __('Receive email alerts from "Contact reporter" requests'),
            'type' => 'checkbox',
            'checked' => isset($this->request->data['User']['contactalert']) ? $this->request->data['User']['contactalert'] : true
        ));
        echo $this->Form->input('disabled', array('type' => 'checkbox', 'label' => __('Immediately disable this user account')));
        echo $this->Form->input('notify', array(
            'label' => __('Send credentials automatically'),
            'type' => 'checkbox',
            'checked' => isset($this->request->data['User']['notify']) ? $this->request->data['User']['notify'] : true
        ));
    ?>
        </div>
    </fieldset>
<?php
    echo $this->Form->button(__('Create user'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'addUser'));
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
