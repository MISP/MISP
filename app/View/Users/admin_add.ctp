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
        if (Configure::read('Plugin.CustomAuth_enable')):
            if (Configure::read('Plugin.CustomAuth_required')):
                $password = false;
            else:
                $userType = Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : 'External authentication';
                echo $this->Form->input('external_auth_required', array('type' => 'checkbox', 'label' => $userType . ' user'));
            endif;

    ?>
        <div class="clear"></div>
        <div id="externalAuthDiv">
        <?php
            echo $this->Form->input('external_auth_key', array('type' => 'text'));
        ?>
        </div>
    <?php
        endif;
    ?>
    <div class="clear"></div>
    <div id="passwordDivDiv">
        <?php
            echo $this->Form->input('enable_password', array('type' => 'checkbox', 'label' => __('Set password')));
        ?>
        <div id="PasswordDiv">
            <div class="clear"></div>
            <?php
                $passwordPopover = '<span class=\"blue bold\">' . __('Length') . '</span>: ' . h($length) . '<br />';
                $passwordPopover .= '<span class=\"blue bold\">' . __('Complexity') . '</span>: ' . h($complexity);
                echo $this->Form->input('password', array(
                    'label' => __('Password') . ' <span id = "PasswordPopover" class="icon-info-sign" ></span>'
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
        $roleOptions = array('label' => __('Role'));
        // We need to make sure that the default role is actually available to the admin (for an org admin it might not be)
        if (!empty($default_role_id) && isset($roles[intval($default_role_id)])) {
            $roleOptions['default'] = $default_role_id;
        }
        echo $this->Form->input('role_id', $roleOptions);
        echo $this->Form->input('authkey', array('value' => $authkey, 'readonly' => 'readonly', 'div' => 'input clear'));
        echo $this->Form->input('nids_sid');
    ?>
        <div id = "syncServers" class="hidden">
    <?php
            echo $this->Form->input('server_id', array('label' => __('Sync user for'), 'div' => 'clear', 'options' => $servers));
    ?>
        </div>
    <?php
        echo $this->Form->input('gpgkey', array('label' => __('GnuPG key'), 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => __('Paste the user\'s GnuPG key here or try to retrieve it from the MIT key server by clicking on "Fetch GnuPG key" below.')));
    ?>
        <div class="clear"><span  role="button" tabindex="0" aria-label="<?php echo __('Fetch the user\'s GnuPG key');?>" onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;"><?php echo __('Fetch GnuPG key');?></span></div>
    <?php
        if (Configure::read('SMIME.enabled')) echo $this->Form->input('certif_public', array('label' => __('SMIME key'), 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => __('Paste the user\'s SMIME public key in PEM format here.')));
        echo $this->Form->input('autoalert', array(
            'label' => __('Receive alerts when events are published'),
            'type' => 'checkbox',
            'checked' => isset($this->request->data['User']['autoalert']) ? $this->request->data['User']['autoalert'] : true
        ));
        echo $this->Form->input('contactalert', array(
            'label' => __('Receive alerts from "contact reporter" requests'),
            'type' => 'checkbox',
            'checked' => isset($this->request->data['User']['contactalert']) ? $this->request->data['User']['contactalert'] : true
        ));
    ?>
        <div class="clear"></div>
    <?php
        echo $this->Form->input('disabled', array('label' => __('Disable this user account')));
        echo $this->Form->input('notify', array(
            'label' => __('Send credentials automatically'),
            'type' => 'checkbox',
            'checked' => isset($this->request->data['User']['notify']) ? $this->request->data['User']['notify'] : true
        ));
    ?>
    </fieldset>
<?php
    echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'addUser'));
?>
<script type="text/javascript">
var syncRoles = <?php echo json_encode($syncRoles); ?>;
$(document).ready(function() {
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
    $('#PasswordPopover').popover("destroy").popover({
        placement: 'right',
        html: 'true',
        trigger: 'hover',
        content: '<?php echo $passwordPopover; ?>'
    });
});
</script>
