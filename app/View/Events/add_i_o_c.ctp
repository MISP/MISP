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
<?php
echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><a href="/events/view/<?php echo $this->request->data['Event']['id'];?>">View Event</a></li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><a href="/events/edit/<?php echo $this->request->data['Event']['id'];?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $this->request->data['Event']['id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $this->request->data['Event']['id'];?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $this->request->data['Event']['id'];?>">Add Attachment</a></li>
		<li class="active"><a href="/events/addIOC/<?php echo $this->request->data['Event']['id'];?>">Populate from IOC</a></li>
		<?php else:	?>
		<li><a href="/shadow_attributes/add/<?php echo $this->request->data['Event']['id'];?>">Propose Attribute</a></li>
		<li><a href="/shadow_attributes/add_attachment/<?php echo $this->request->data['Event']['id'];?>">Propose Attachment</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<?php if ( 0 == $this->request->data['Event']['published'] && ($isAdmin || $mayPublish)): ?>
		<li><?php echo $this->Form->postLink('Publish Event', array('action' => 'alert', $this->request->data['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?'); ?></li>
		<li><?php echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $this->request->data['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!'); ?></li>
		<?php else: ?>
		<!-- ul><li>Alert already sent</li></ul -->
		<?php endif; ?>
		<li><a href="/events/contact/<?php echo $this->request->data['Event']['id'];?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $this->request->data['Event']['id'];?>">Download as XML</a></li>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $this->request->data['Event']['id'];?>">Download as IOC</a></li>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>