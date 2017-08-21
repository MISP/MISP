<div class="users form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php echo __('Change Password'); ?></legend>
	<?php
		$passwordPopover = '<span class=\"blue bold\">Length</span>: ' . h($length) . '<br />';
		$passwordPopover .= '<span class=\"blue bold\">Complexity</span>: ' . h($complexity);
		echo $this->Form->input('password', array(
			'label' => 'Password <span id = "PasswordPopover" class="icon-info-sign" ></span>'
		));
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
	?>
	</fieldset>
	<div style="border-bottom: 1px solid #e5e5e5;width:100%;">&nbsp;</div>
	<div class="clear" style="margin-top:10px;">
<?php
	if (Configure::read('Security.require_password_confirmation')) {
		echo $this->Form->input('current_password', array('type' => 'password', 'div' => false, 'class' => 'input password required', 'label' => 'Confirm with your current password'));
	}
?>
	</div>
<?php
echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'news'));
?>
