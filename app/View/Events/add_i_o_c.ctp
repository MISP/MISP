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
		<li><?php echo $this->Html->link('View Event', array('controller' => 'events', 'action' => 'view', $id)); ?> </li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><?php echo $this->Html->link('Edit Event', array('controller' => 'events', 'action' => 'edit', $id)); ?> </li>
		<li><?php echo $this->Form->postLink('Delete Event', array('controller' => 'events', 'action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id)); ?></li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $id));?> </li>
		<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $id));?> </li>
		<li class="active"><?php echo $this->Html->link('Populate event from IOC', array('controller' => 'events', 'action' => 'addIOC', $id));?> </li>
		<?php else:	?>
		<li><?php echo $this->Html->link('Propose Attribute', array('controller' => 'shadow_attributes', 'action' => 'add', $id));?> </li>
		<li><?php echo $this->Html->link('Propose Attachment', array('controller' => 'shadow_attributes', 'action' => 'add_attachment', $id));?> </li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link(__('Contact reporter', true), array('controller' => 'events', 'action' => 'contact', $id)); ?> </li>
		<li><?php echo $this->Html->link(__('Download as XML', true), array('controller' => 'events', 'action' => 'xml', 'download', $id)); ?></li>
		<li><?php echo $this->Html->link(__('Download as IOC', true), array('controller' => 'events', 'action' => 'downloadOpenIOCEvent', $id)); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
		<?php endif; ?>
	</ul>
</div>