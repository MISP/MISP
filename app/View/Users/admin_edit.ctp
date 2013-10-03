<div class="users form">
<?php echo $this->Form->create('User', array('novalidate'=>true));?>
	<fieldset>
		<legend><?php echo __('Admin Edit User'); ?></legend>
	<?php
		echo $this->Form->input('email');
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
		if ($isSiteAdmin) {
			echo $this->Form->input('org', array('label' => 'Organisation'));
		}
		echo $this->Form->input('role_id', array('label' => 'Role', 'div' => 'input clear'));	// TODO ACL, User edit role_id.
		echo $this->Form->input('authkey', array('disabled' => 'disabled', 'label' => 'Authentication key'));
		echo $this->Form->input('nids_sid');
		echo $this->Form->input('newsread', array(
				'label' => 'News read (date)',
				'type' => 'text',
				'class' => 'datepicker',
		));
		echo $this->Form->input('gpgkey', array('label' => 'GPG key', 'div' => 'clear', 'class' => 'input-xxlarge'));
		echo $this->Form->input('termsaccepted', array('label' => 'Terms accepted'));
		echo $this->Form->input('change_pw', array('type' => 'checkbox', 'label' => 'Change Password'));
		echo $this->Form->input('autoalert', array('label' => 'Receive alerts when events are published'));
		echo $this->Form->input('contactalert', array('label' => 'Receive alerts from "contact reporter" requests'));

		echo $this->Html->link('Reset Auth Key', array('controller' => 'users', 'action' => 'resetauthkey', $currentId));
	?>
	</fieldset>
<?php
	echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('New User', array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link('List Users', array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
		<li class="divider"></li>
		<?php if ($isSiteAdmin): ?>
		<li><?php echo $this->Html->link('New Role', array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
		<?php endif; ?>
		<li><?php echo $this->Html->link('List Roles', array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
		<?php if ($isSiteAdmin): ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Contact users', array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
		<?php endif; ?>
	</ul>
</div>

