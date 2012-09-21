<div class="events index">
	<h2>Events</h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<?php if ('true' == Configure::read('CyDefSIG.showowner') || $isAdmin): ?>
			<th><?php echo $this->Paginator->sort('user_id', 'Email');?></th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('date');?></th>
			<th<?php echo ' title="' . $eventDescriptions['risk']['desc'] . '"';?>>
			<?php echo $this->Paginator->sort('risk');?></th>
			<th><?php echo $this->Paginator->sort('info');?></th>
			<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
			<th<?php echo ' title="' . $eventDescriptions['private']['desc'] . '"';?>>
			<?php echo $this->Paginator->sort('private');?></th>
			<?php endif; ?>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($events as $event):
	?>
	<tr>
		<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
		<?php
		echo $this->Html->image('orgs/' . h($event['Event']['org']) . '.png', array('alt' => h($event['Event']['org']),'width' => '50','hight' => '50'));
		?>
		&nbsp;</td>
		<?php endif; ?>
		<td class="short">
		<?php echo $this->Html->link($event['Event']['id'], array('controller' => 'events', 'action' => 'view', $event['Event']['id'])); ?>
		&nbsp;</td>

		<?php if ('true' == Configure::read('CyDefSIG.showowner') || $isAdmin): ?>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
		<?php echo h($event['User']['email']); ?>&nbsp;</td>
		<?php endif; ?>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
		<?php echo $event['Event']['date']; ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
		<?php echo $event['Event']['risk']; ?>&nbsp;</td>
		<td onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
		<?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;</td>
		<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
		<?php echo ($event['Event']['private'])? 'Private' : ''; ?>&nbsp;</td>
		<?php endif; ?>
		<td class="actions">
			<?php
			if (0 == $event['Event']['published'] && ($isAdmin || $event['Event']['org'] == $me['org']))
				echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?');
			elseif (0 == $event['Event']['published']) echo 'Not published';
			?>
<?php
if ($isAdmin || $event['Event']['org'] == $me['org']) {
	echo $this->Html->link(__('Edit', true), array('action' => 'edit', $event['Event']['id']));
	echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id']));
}
?>
			<?php echo $this->Html->link(__('View', true), array('controller' => 'events', 'action' => 'view', $event['Event']['id'])); ?>
		</td>
	</tr>
<?php endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	));
	?>	</p>

	<div class="paging">
	<?php
		echo $this->Paginator->prev('< ' . __('previous'), array(), null, array('class' => 'prev disabled'));
		echo $this->Paginator->numbers(array('separator' => ''));
		echo $this->Paginator->next(__('next') . ' >', array(), null, array('class' => 'next disabled'));
	?>
	</div>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
