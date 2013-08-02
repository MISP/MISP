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
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><a href="/events/view/<?php echo $id;?>">View Event</a></li>
		<li><a href="/logs/event_index/<?php echo $id;?>">View Event History</a></li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><a href="/events/edit/<?php echo $id;?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id)); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $id;?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $id;?>">Add Attachment</a></li>
		<li class="active"><a href="/events/addIOC/<?php echo $id;?>">Populate from IOC</a></li>
		<li><a href="/attributes/add_threatconnect/<?php echo $id; ?>">Populate from ThreatConnect</a></li>
		<?php else:	?>
		<li><a href="/shadow_attributes/add/<?php echo $id;?>">Propose Attribute</a></li>
		<li><a href="/shadow_attributes/add_attachment/<?php echo $id;?>">Propose Attachment</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/contact/<?php echo $id;?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $id;?>">Download as XML</a></li>
		<?php if ($published): ?>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $id;?>">Download as IOC</a></li>
		<li><a href="/events/csv/download/<?php echo $id;?>">Download as CSV</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>