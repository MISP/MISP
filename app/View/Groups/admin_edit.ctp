<div class="groups form">
<?php echo $this->Form->create('Group');?>
	<fieldset>
		<legend><?php echo __('Edit Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->radio('permission', $options, array('label' => 'Permissions'));?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
