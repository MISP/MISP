<div class="users form">
    <?php echo $this->Form->create('User');?>
    <fieldset>
        <legend><?php echo __('Reset password'); ?></legend>
    <?php
        $passwordPopover = '<span class="blue bold">' . __('Minimal length') . '</span>: ' . h($length) . '<br>';
        $passwordPopover .= '<span class="blue bold">' . __('Complexity') . '</span>: ' . h($complexity);
        echo $this->Form->input('password', array(
            'label' => __('New password') . ' <span id="PasswordPopover" data-content="' . h($passwordPopover) . '" class="fas fa-info-circle"></span>', 'autofocus'
        ));
        echo $this->Form->input('confirm_password', [
            'type' => 'password',
            'label' => __('Confirm new password'),
            'div' => array('class' => 'input password required'),
        ]);
    ?>
    </fieldset>
    <div style="border-bottom: 1px solid #e5e5e5;width:100%;">&nbsp;</div>
    <div class="clear" style="margin-top:10px;">
    </div>
<?php
echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
