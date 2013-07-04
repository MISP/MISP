<div class="users form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php echo __('Change Password'); ?></legend>
	<?php
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
	?>
	</fieldset>
<?php
echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
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