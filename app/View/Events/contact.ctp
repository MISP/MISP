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
		<li><?php echo $this->Html->link('View Event', array('controller' => 'events', 'action' => 'view', $this->request->data['Event']['id'])); ?> </li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><?php echo $this->Html->link('Edit Event', array('controller' => 'events', 'action' => 'edit', $this->request->data['Event']['id'])); ?> </li>
		<li><?php echo $this->Form->postLink('Delete Event', array('controller' => 'events', 'action' => 'delete', $this->request->data['Event']['id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $this->request->data['Event']['id']));?> </li>
		<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $this->request->data['Event']['id']));?> </li>
		<li><?php echo $this->Html->link('Populate event from IOC', array('controller' => 'events', 'action' => 'addIOC', $this->request->data['Event']['id']));?> </li>
		<?php else:	?>
		<li><?php echo $this->Html->link('Propose Attribute', array('controller' => 'shadow_attributes', 'action' => 'add', $this->request->data['Event']['id']));?> </li>
		<li><?php echo $this->Html->link('Propose Attachment', array('controller' => 'shadow_attributes', 'action' => 'add_attachment', $this->request->data['Event']['id']));?> </li>
		<?php endif; ?>
		<li class="divider"></li>
		<li class="active"><?php echo $this->Html->link(__('Contact reporter', true), array('controller' => 'events', 'action' => 'contact', $this->request->data['Event']['id'])); ?> </li>
		<li><?php echo $this->Html->link(__('Download as XML', true), array('controller' => 'events', 'action' => 'xml', 'download', $this->request->data['Event']['id'])); ?></li>
		<li><?php echo $this->Html->link(__('Download as IOC', true), array('controller' => 'events', 'action' => 'downloadOpenIOCEvent', $this->request->data['Event']['id'])); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
		<?php endif; ?>
	</ul>
</div>