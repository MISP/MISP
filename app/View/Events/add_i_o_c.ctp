<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
	<fieldset>
		<legend><?php echo __('Import OpenIOC'); ?></legend>
<?php
echo $this->Form->input('Event.submittedioc', array(
		'label' => '<b>OpenIOC</b>',
		'type' => 'file',
));
?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
