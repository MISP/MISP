<div class="users form">
<?php echo $this->Form->create('User', array('novalidate'=>true));?>
	<fieldset>
		<legend><?php echo __('Admin Add User'); ?></legend>
	<?php
		echo $this->Form->input('email');
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
		if ($currentOrg == 'ADMIN') {
			echo $this->Form->input('org', array('label' => 'Organisation'));
		}
		echo $this->Form->input('role_id', array('label' => 'Role', 'div' => 'input clear'));
		echo $this->Form->input('authkey', array('value' => $authkey, 'readonly' => 'readonly'));
		echo $this->Form->input('nids_sid');
		echo $this->Form->input('gpgkey', array('label' => 'GPG key', 'div' => 'clear', 'class' => 'input-xxlarge'));
		echo $this->Form->input('autoalert', array('label' => 'Receive alerts when events are published'));
		echo $this->Form->input('contactalert', array('label' => 'Receive alerts from "contact reporter" requests'));

	?>
	</fieldset>
<?php echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li class="active"><a href="/admin/users/add">New User</a></li>
		<li><a href="/admin/users/index">List Users</a></li>
		<li class="divider"></li>
		<?php if ($isSiteAdmin): ?>
		<li><a href="/admin/roles/add">New Role</a></li>
		<?php endif; ?>
		<li><a href="/admin/roles/index">List Role</a></li>
		<?php if ($isSiteAdmin): ?>
		<li class="divider"></li>
		<li><a href="/admin/users/email">Contact Users</a></li>
		<?php endif; ?>
	</ul>
</div>