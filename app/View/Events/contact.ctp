<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo 'Contact reporter of event '.$this->Form->value('Event.id'); ?></legend>
		<p>You are about to contact the person who reported event <?php echo $this->Form->value('Event.id'); ?>.<br/>
		Feel free to add a custom message that will be sent to the reporter. <br/>
		Your email address and details about the event will be added automagically to the message.</p>
	<?php
		echo $this->Form->input('message', array('type'=> 'textarea'));
	?>
	<?php echo $this->Form->end(__('Submit', true));?>
	</fieldset>

</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>

	</ul>
</div>
