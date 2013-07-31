<?php echo $this->element('bread_crumbs'); ?>
<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data'));?>
	<fieldset>
		<legend>Import ThreatConnect CSV file</legend>
		<?php
		echo $this->Form->hidden('event_id');
		?>
		<div class="input clear"></div>
		<div class="input">
		<?php
		echo $this->Form->file('value', array(
			'error' => array('escape' => false),
		));
		?>
		</div>
	</fieldset>
<?php
echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions  <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><a href="/events/view/<?php echo $this->request->data['Attribute']['event_id']; ?>">View Event</a></li>
		<li><a href="/logs/event_index/<?php echo $this->request->data['Attribute']['event_id'];?>">View Event History</a></li>
		<li><a href="/events/edit/<?php echo $this->request->data['Attribute']['event_id']; ?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('controller' => 'events', 'action' => 'delete', $this->request->data['Attribute']['event_id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Attribute']['event_id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $this->request->data['Attribute']['event_id']; ?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $this->request->data['Attribute']['event_id']; ?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $this->request->data['Attribute']['event_id']; ?>">Populate from IOC</a></li>
		<li class="active"><a href="/attributes/add_threatconnect/<?php echo $this->request->data['Attribute']['event_id']; ?>">Populate from ThreatConnect</a></li>
		<li class="divider"></li>
		<li><a href="/events/contact/<?php echo $this->request->data['Attribute']['event_id']; ?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $this->request->data['Attribute']['event_id']; ?>">Download as XML</a></li>
		<?php if ($published): ?>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $this->request->data['Attribute']['event_id'];?>">Download as IOC</a></li>
		<li><a href="/events/csv/download/<?php echo $this->request->data['Attribute']['event_id'];?>">Download as CSV</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>
