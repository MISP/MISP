<div class="groups form">
<?php echo $this->Form->create('Group');?>
	<fieldset>
		<legend><?php echo __('Add Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->radio('permission', $options, array('value' => '3'));?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
