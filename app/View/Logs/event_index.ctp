<div class="logs index">
<h2>Logs</h2>
	<div class="pagination">
		<ul>
			<?php
			$this->Paginator->options(array(
				'update' => '.span12',
				'evalScripts' => true,
				'before' => '$(".progress").show()',
				'complete' => '$(".progress").hide()',
			));

			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
			?>
		</ul>
	</div>
	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th><?php echo $this->Paginator->sort('model');?></th>
			<th><?php echo $this->Paginator->sort('action');?></th>
			<th><?php echo $this->Paginator->sort('created');?></th>
			<th><?php echo $this->Paginator->sort('title');?></th>
		</tr>
		<?php foreach ($list as $item): ?>
		<tr>
			<td class="short"><?php echo (h($item['Log']['model']) . '(' . h($item['Log']['model_id']) . ')'); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Log']['action']); ?>&nbsp;</td>
			<td class="short"><?php echo (h($item['Log']['created'])); ?>&nbsp;</td>
			<td><?php echo h($item['Log']['title']); ?>&nbsp;</td>
		</tr>
		<?php endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	));
	?>
	</p>
	<div class="pagination">
		<ul>
		<?php
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><a href="/events/view/<?php echo $eventId;?>">View Event</a></li>
		<li class="active"><a href="/logs/event_index/<?php echo $eventId;?>">View Event History</a></li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><a href="/events/edit/<?php echo $eventId;?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('controller' => 'events', 'action' => 'delete', $eventId), null, __('Are you sure you want to delete # %s?', $eventId)); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $eventId;?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $eventId;?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $eventId;?>">Populate event from IOC</a></li>
		<?php else:	?>
		<li><a href="/shadow_attributes/add/<?php echo $eventId;?>">Propose Attribute</a></li>
		<li><a href="/shadow_attributes/add_attachment/<?php echo $eventId;?>">Propose Attachment</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/contact/<?php echo $eventId;?>">Contact reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $eventId;?>">Download as XML</a></li>
		<?php if ($published): ?>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $eventId;?>">Download as IOC</a></li>
		<li><a href="/events/csv/download/<?php echo $eventId;?>">Download as CSV</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>
