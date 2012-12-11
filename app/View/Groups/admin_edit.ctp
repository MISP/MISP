<div class="groups form">
<?php echo $this->Form->create('Group');?>
	<fieldset>
		<legend><?php echo __('Edit Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->radio('permission', $options, array('label' => 'Permissions'));?>
		<?php echo $this->Form->input('perm_sync', array('type' => 'checkbox', 'label' => 'Sync Actions'));?>
		<?php echo $this->Form->input('perm_admin', array('type' => 'checkbox', 'label' => 'Administration Actions'));?>
		<?php echo $this->Form->input('perm_audit', array('type' => 'checkbox', 'label' => 'Audit Actions'));?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
<script type="text/javascript">
// TODO only be able to tick perm_sync if manage org events and above.
</script>
<?php echo $this->Js->writeBuffer(); // Write cached s