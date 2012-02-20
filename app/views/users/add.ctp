<div class="users form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php __('Add User'); ?></legend>
	<?php
		echo $this->Form->input('group_id');
		echo $this->Form->input('email');
		echo $this->Form->input('password');
		echo $this->Form->input('org');
		echo $this->Form->input('autoalert');
		echo $this->Form->input('snort_sid');
		echo $this->Form->input('gpgkey');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
