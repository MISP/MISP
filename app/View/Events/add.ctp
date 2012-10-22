<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
	<fieldset>
		<legend><?php echo __('Add Event'); ?></legend>
<?php
echo $this->Form->input('date');
if ('true' == Configure::read('CyDefSIG.sync')) {
	if ('true' == Configure::read('CyDefSIG.private')) {
		echo $this->Form->input('sharing', array('label' => 'Distribution',
			'before' => $this->Html->div('forminfo', isset($eventDescriptions['sharing']['formdesc']) ? $eventDescriptions['sharing']['formdesc'] : $eventDescriptions['sharing']['desc']),));
	} else {
		echo $this->Form->input('private', array(
		'before' => $this->Html->div('forminfo', isset($eventDescriptions['private']['formdesc']) ? $eventDescriptions['private']['formdesc'] : $eventDescriptions['private']['desc']),));
	}
}
echo $this->Form->input('risk', array(
		'before' => $this->Html->div('forminfo', isset($eventDescriptions['risk']['formdesc']) ? $eventDescriptions['risk']['formdesc'] : $eventDescriptions['risk']['desc'])));
echo $this->Form->input('info');
echo $this->Form->input('Event.submittedfile', array(
		'label' => '<b>GFI sandbox</b>',
		'between' => '<br />',
		'type' => 'file',
		'before' => $this->Html->div('forminfo', isset($eventDescriptions['submittedfile']['formdesc']) ? $eventDescriptions['submittedfile']['formdesc'] : $eventDescriptions['submittedfile']['desc'])));

?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>

	</ul>
</div>
