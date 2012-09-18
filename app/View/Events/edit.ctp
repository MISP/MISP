<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Edit Event'); ?></legend>
<?php
echo $this->Form->input('id');
echo $this->Form->input('date');
echo $this->Form->input('risk', array(
		'before' => $this->Html->div('forminfo', isset($event_descriptions['risk']['formdesc']) ? $event_descriptions['risk']['formdesc'] : $event_descriptions['risk']['desc'])));
if ('true' == Configure::read('CyDefSIG.sync')) {
	echo $this->Form->input('private', array(
		'before' => $this->Html->div('forminfo', isset($event_descriptions['private']['formdesc']) ? $event_descriptions['private']['formdesc'] : $event_descriptions['private']['desc']),));
}
echo $this->Form->input('info');
?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<ul>

		<li><?php echo $this->Html->link(__('Delete', true), array('action' => 'delete', $this->Form->value('Event.id')), null, sprintf(__('Are you sure you want to delete # %s?', true), $this->Form->value('Event.id'))); ?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>