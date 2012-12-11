<div class="groups form">
<?php echo $this->Form->create('Group');?>
	<fieldset>
		<legend><?php echo __('Add Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->radio('permission', $options, array('value' => '3'));?>
		<?php echo $this->Form->input('perm_sync', array('type' => 'checkbox', 'checked' => false, 'label' => 'Sync Actions'));?>
		<?php echo $this->Form->input('perm_admin', array('type' => 'checkbox', 'checked' => false, 'label' => 'Administration Actions'));?>
		<?php echo $this->Form->input('perm_audit', array('type' => 'checkbox', 'checked' => false, 'label' => 'Audit Actions'));?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
