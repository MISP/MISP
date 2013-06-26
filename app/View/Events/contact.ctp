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
		<li><a href="/events/view/<?php echo $this->data['Event']['id'];?>">View Event</a></li>
		<li><a href="/logs/event_index/<?php echo $this->data['Event']['id'];?>">View Event History</a></li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><a href="/events/edit/<?php echo $this->data['Event']['id'];?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $this->data['Event']['id']), null, __('Are you sure you want to delete # %s?', $this->data['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $this->data['Event']['id'];?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $this->data['Event']['id'];?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $this->data['Event']['id'];?>">Populate from IOC</a></li>
		<?php else:	?>
		<li><a href="/shadow_attributes/add/<?php echo $this->data['Event']['id'];?>">Propose Attribute</a></li>
		<li><a href="/shadow_attributes/add_attachment/<?php echo $this->data['Event']['id'];?>">Propose Attachment</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li class="active"><a href="/events/contact/<?php echo $this->data['Event']['id'];?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $this->data['Event']['id'];?>">Download as XML</a></li>
		<?php if ($this->data['Event']['published']): ?>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $this->data['Event']['id'];?>">Download as IOC</a></li>
		<li><a href="/events/csv/download/<?php echo $this->data['Event']['id'];?>">Download as CSV</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>
