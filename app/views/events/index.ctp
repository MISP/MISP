<div class="events index">
	<h2>Events</h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('date');?></th>
			<th><?php echo $this->Paginator->sort('risk');?></th>
			<th><?php echo $this->Paginator->sort('info');?></th>
			<th class="actions"><?php __('Actions');?></th>
	</tr>
	<?php
	$i = 0;
	foreach ($events as $event):
		$class = null;
		if ($i++ % 2 == 0) {
			$class = ' class="altrow"';
		}
	?>
	<tr<?php echo $class;?> onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true) ;?>';">
		<td style="white-space: nowrap"><?php echo $event['Event']['id']; ?>&nbsp;</td>
		<td style="white-space: nowrap"><?php echo Sanitize::html($event['Event']['org']); ?>&nbsp;</td>
		<td style="white-space: nowrap"><?php echo $event['Event']['date']; ?>&nbsp;</td>
		<td style="white-space: nowrap"><?php echo $event['Event']['risk']; ?>&nbsp;</td>
		<td><?php echo nl2br(Sanitize::html($event['Event']['info'])); ?>&nbsp;</td>
		<td class="actions" style="text-align:right;">
			<?php 
			if (0 == $event['Event']['alerted'] && ($isAdmin || $event['Event']['org'] == $me['org'])) echo $this->Html->link(__('Finish Edit', true), array('action' => 'alert', $event['Event']['id']), array(), 'Are you sure this event is complete and everyone should be alerted?'); 
			elseif (0 == $event['Event']['alerted']) echo 'Not finished editing';
			?>
			<?php 
			if ($isAdmin || $event['Event']['org'] == $me['org']) {
  			   echo $this->Html->link(__('Edit', true), array('action' => 'edit', $event['Event']['id']));
  			   echo $this->Html->link(__('Delete', true), array('action' => 'delete', $event['Event']['id']), null, sprintf(__('Are you sure you want to delete # %s?', true), $event['Event']['id'])); 
			}
			?>
			<?php echo $this->Html->link(__('View', true), array('action' => 'view', $event['Event']['id'])); ?>
		</td>
	</tr>
<?php endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page %page% of %pages%, showing %current% records out of %count% total, starting on record %start%, ending on %end%', true)
	));
	?>	</p>

	<div class="paging">
		<?php echo $this->Paginator->prev('<< ' . __('previous', true), array(), null, array('class'=>'disabled'));?>
	 | 	<?php echo $this->Paginator->numbers();?>
 |
		<?php echo $this->Paginator->next(__('next', true) . ' >>', array(), null, array('class' => 'disabled'));?>
	</div>
</div>
<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
		<?php echo $this->element('actions_menu'); ?>

	</ul>
</div>
