<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Contact organization reporting event ', true) . $this->Form->value('Event.id'); ?></legend>
		<p>You are about to contact the organization that reported event <?php echo $this->Form->value('Event.id'); ?>.<br/>
		Feel free to add a custom message that will be sent to the reporting organization. <br/>
		Your email address and details about the event will be added automagically to the message.</p>
	<?php
		echo $this->Form->input('message', array('type' => 'textarea'));
echo $this->Form->input('person', array(
			'label' => __('Submit only to person', true),
			'type' => 'checkbox',
			'after' => $this->Html->div('forminfo', __('By selecting this box you will contact the creator of the event only.', true)),
));	?>
	<?php echo $this->Form->end(__('Submit to Org', true));?>
	</fieldset>

</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>

	</ul>
</div>
