<div class="users form">
<?php echo $this->Form->create('User', array('novalidate' => true));?>
    <fieldset>
        <legend><?php echo __('Edit My Profile'); ?></legend>
    <?php
        echo $this->Form->input('email', ['disabled' => $canChangeLogin ? false : 'disabled']);
    ?>
        <div class="input clear"></div>
    <?php
    if ($canChangePassword) {
        $passwordPopover = '<span class="blue bold">' . __('Minimal length') . '</span>: ' . h($length) . '<br>';
        $passwordPopover .= '<span class="blue bold">' . __('Complexity') . '</span>: ' . h($complexity);
        echo $this->Form->input('password', array(
            'label' => __('Password') . ' <span id="PasswordPopover" data-content="' . h($passwordPopover) . '" class="fas fa-info-circle"></span>'
        ));
        echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
    }
    ?>
        <div class="input clear"></div>
    <?php
        echo $this->Form->input('nids_sid', ['label' => __('NIDS SID')]);
    ?>
        <div class="input clear"></div>
    <?php
        $placeholder = $canFetchPgpKey ? __('Paste yours PGP key here or try to retrieve it from the CIRCL key server by clicking on "Fetch PGP key" below.') :
            __('Paste yours PGP key here');
        echo $this->Form->input('gpgkey', array('label' => __('PGP key'), 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => $placeholder));
        if ($canFetchPgpKey):
        ?>
            <div class="clear"><span role="button" tabindex="0" aria-label="<?= __('Fetch PGP key');?>" onclick="lookupPGPKey();" class="btn btn-inverse" style="margin-bottom:10px;"><?= __('Fetch PGP key');?></span></div>
        <?php
        endif;
        if (Configure::read('SMIME.enabled')) {
            echo $this->Form->input('certif_public', array('label' => __('S/MIME Public certificate (PEM format)'), 'div' => 'clear', 'class' => 'input-xxlarge'));
        }
        echo '<div class="user-edit-checkboxes">';
        echo $this->Form->input('contactalert', array('label' => __('Receive email alerts from "Contact reporter" requests'), 'type' => 'checkbox'));
        echo '</div>';
    ?>
    <h5><?= __('Subscribe to the following notification:') ?></h5>
    <div class="user-edit-checkboxes">
        <?php
        echo $this->Form->input('autoalert', array('label' => __('Event published notification'), 'type' => 'checkbox'));
        echo $this->Form->input('notification_daily', array('label' => __('Daily notifications'), 'type' => 'checkbox'));
        echo $this->Form->input('notification_weekly', array('label' => __('Weekly notifications'), 'type' => 'checkbox'));
        echo $this->Form->input('notification_monthly', array('label' => __('Monthly notifications'), 'type' => 'checkbox'));
        ?>
    </div>
    <div style="border-bottom: 1px solid #e5e5e5;width:100%;">&nbsp;</div>
    <div class="clear" style="margin-top:10px;">
<?php
    if (Configure::read('Security.require_password_confirmation')) {
        echo $this->Form->input('current_password', array('type' => 'password', 'div' => false, 'class' => 'input password required', 'label' => __('Confirm with your current password')));
    }
?>
    </div>
<?php
    echo $this->Form->button(__('Edit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    $user['User']['id'] = $id;
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'edit', 'user' => $user));
?>
