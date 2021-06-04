<div class="users form">
    <?php echo $this->Form->create('User');?>
    <fieldset>
        <legend><?php echo __('Change Password'); ?></legend>
    <?php
        $passwordPopover = '<span class="blue bold">' . __('Minimal length') . '</span>: ' . h($length) . '<br>';
        $passwordPopover .= '<span class="blue bold">' . __('Complexity') . '</span>: ' . h($complexity);
        echo $this->Form->input('password', array(
            'label' => __('Password') . ' <span id="PasswordPopover" data-content="' . h($passwordPopover) . '" class="fas fa-info-circle"></span>', 'autofocus'
        ));
        echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'change_pw'));
?>
