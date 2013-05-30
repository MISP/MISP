<div class="users form">
<?php echo $this->Form->create('User', array('novalidate' => true));?>
	<fieldset>
		<legend><?php echo __('Edit User'); ?></legend>
	<?php
		echo $this->Form->input('email');
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
		if ($isAdmin) echo $this->Form->input('org', array('label' => 'Organisation'));
		else echo $this->Form->input('org', array('disabled' => 'disabled', 'label' => 'Organisation'));
		if ($isAdmin) echo $this->Form->input('role_id');
		else echo $this->Form->input('role_id', array('disabled' => 'disabled'));	// TODO ACL, check, My Profile not edit role_id.
		echo $this->Form->input('autoalert', array('label' => 'Receive alerts when events are published'));
		echo $this->Form->input('contactalert', array('label' => 'Receive alerts from "contact reporter" requests'));
		echo $this->Form->input('nids_sid');
		echo $this->Form->input('gpgkey', array('label' => 'GPG key'));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>

