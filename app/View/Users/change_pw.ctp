<div class="users form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php echo __('Change Password'); ?></legend>
	<?php
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>

<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
