<?php
$mayModify = (($isAclModify && $this->request->data['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $this->request->data['Event']['orgc'] == $me['org']));
$mayPublish = ($isAclPublish && $this->request->data['Event']['orgc'] == $me['org']);
?>
<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Contact organization reporting event ', true) . $this->Form->value('Event.id'); ?></legend>
		<p>You are about to contact the organization that reported event <?php echo $this->Form->value('Event.id'); ?>.<br/>
		Feel free to add a custom message that will be sent to the reporting organization. <br/>
		Your email address and details about the event will be added automagically to the message.</p>
	<?php
		echo $this->Form->input('message', array(
			'type' => 'textarea',
			'class' => 'input-xxlarge',
		));
	?>
		<div class="input clear"></div>
	<?php
		echo $this->Form->input('person', array(
			'label' => __('Submit only to person', true),
			'type' => 'checkbox',
			'class' => 'clear',
			'after' => $this->Html->div('forminfo', __('By selecting this box you will contact the creator of the event only.', true)),
		));
	?>
		<div class="input clear">
	<?php
		echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
		echo $this->Form->end();
	?>
		</div>
	</fieldset>

</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><a href="/events/view/<?php echo $event['Event']['id'];?>">View Event</a></li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><a href="/events/edit/<?php echo $event['Event']['id'];?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $event['Event']['id'];?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $event['Event']['id'];?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $event['Event']['id'];?>">Populate from IOC</a></li>
		<?php else:	?>
		<li><a href="/shadow_attributes/add/<?php echo $event['Event']['id'];?>">Propose Attribute</a></li>
		<li><a href="/shadow_attributes/add_attachment/<?php echo $event['Event']['id'];?>">Propose Attachment</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<?php if ( 0 == $event['Event']['published'] && ($isAdmin || $mayPublish)): ?>
		<li><?php echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?'); ?></li>
		<li><?php echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $event['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!'); ?></li>
		<?php else: ?>
		<!-- ul><li>Alert already sent</li></ul -->
		<?php endif; ?>
		<li class="active"><a href="/events/contact/<?php echo $event['Event']['id'];?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $event['Event']['id'];?>">Download as XML</a></li>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $event['Event']['id'];?>">Download as IOC</a></li>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>
