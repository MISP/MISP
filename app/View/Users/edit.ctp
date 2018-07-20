<div class="users form">
<?php echo $this->Form->create('User', array('novalidate' => true));?>
    <fieldset>
        <legend><?php echo __('Edit My Profile'); ?></legend>
    <?php
        echo $this->Form->input('email');
    ?>
        <div class="input clear"></div>
    <?php
        $passwordPopover = '<span class=\"blue bold\">Length</span>: ' . h($length) . '<br />';
        $passwordPopover .= '<span class=\"blue bold\">Complexity</span>: ' . h($complexity);
        echo $this->Form->input('password', array(
            'label' => 'Password <span id = "PasswordPopover" class="icon-info-sign" ></span>'
        ));
        echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
    ?>
        <div class="input clear"></div>
    <?php
        echo $this->Form->input('nids_sid');
    ?>
        <div class="input clear"></div>
    <?php
        echo $this->Form->input('gpgkey', array('label' => 'GnuPG key', 'div' => 'clear', 'class' => 'input-xxlarge'));
        ?>
            <div class="clear"><span role="button" tabindex="0" aria-label="<?php echo __('Fetch GnuPG key');?>" onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;"><?php echo __('Fetch GnuPG key');?></span></div>
        <?php
        if (Configure::read('SMIME.enabled')) echo $this->Form->input('certif_public', array('label' => __('SMIME Public certificate (PEM format)'), 'div' => 'clear', 'class' => 'input-xxlarge'));
        echo $this->Form->input('autoalert', array('label' => __('Receive alerts when events are published'), 'type' => 'checkbox'));
        echo $this->Form->input('contactalert', array('label' => __('Receive alerts from "contact reporter" requests'), 'type' => 'checkbox'));
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
    echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    $user['User']['id'] = $id;
    echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'edit', 'user' => $user));
?>
<script type="text/javascript">
    $(document).ready(function() {
        $('#PasswordPopover').popover("destroy").popover({
            placement: 'right',
            html: 'true',
            trigger: 'hover',
            content: '<?php echo $passwordPopover; ?>'
        });
    });
</script>
<?php echo $this->Js->writeBuffer();
