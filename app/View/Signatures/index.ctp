<div class="signatures index">
	<h2><?php echo __('Signatures');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('event_id');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th>To IDS</th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($signatures as $signature): ?>
	<tr>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $signature['Signature']['event_id']), true) ;?>';">
			<?php echo $this->Html->link($signature['Event']['id'], array('controller' => 'events', 'action' => 'view', $signature['Event']['id'])); ?>
		</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $signature['Signature']['event_id']), true) ;?>';">
		<?php echo h($signature['Signature']['type']); ?>&nbsp;</td>
		<td onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $signature['Signature']['event_id']), true) ;?>';">
		<?php echo nl2br(Sanitize::html($signature['Signature']['value'])); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $signature['Signature']['event_id']), true) ;?>';">
		<?php echo $signature['Signature']['to_ids'] ? 'Yes' : 'No'; ?>&nbsp;</td>
		<td class="actions"><?php 
			if ($isAdmin || $signature['Event']['org'] == $me['org']) {
				echo $this->Html->link(__('Edit'), array('action' => 'edit', $signature['Signature']['id'])); 
				echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $signature['Signature']['id']), null, __('Are you sure you want to delete this signature?')); 
			}
			echo $this->Html->link(__('View'), array('controller' => 'events', 'action' => 'view', $signature['Signature']['event_id']));
			?>
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
