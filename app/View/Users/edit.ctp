<div class="users form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php echo __('Edit User'); ?></legend>
	<?php
		echo $this->Form->input('email');
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
		if ($isAdmin) echo $this->Form->input('org');
		else echo $this->Form->input('org', array('disabled' => 'disabled'));
		if ($isAdmin) echo $this->Form->input('role_id');
		else echo $this->Form->input('role_id', array('disabled' => 'disabled'));	// TODO ACL, check, My Profile not edit role_id.
		echo $this->Form->input('autoalert');
		echo $this->Form->input('nids_sid');
		echo $this->Form->input('gpgkey');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>

<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
