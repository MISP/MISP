<div class="signatures index">
	<h2><?php __('Signatures');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('event_id');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th>To IDS</th>
			<th class="actions"><?php __('Actions');?></th>
	</tr>
	<?php
	$i = 0;
	foreach ($signatures as $signature):
		$class = null;
		if ($i++ % 2 == 0) {
			$class = ' class="altrow"';
		}
	?>
	<tr<?php echo $class;?> onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $signature['Signature']['event_id']), true) ;?>';">
		<td>
			<?php echo $this->Html->link($signature['Event']['id'], array('controller' => 'events', 'action' => 'view', $signature['Event']['id'])); ?>
		</td>
		<td><?php echo $signature['Signature']['type']; ?>&nbsp;</td>
		<td><?php echo nl2br(Sanitize::html($signature['Signature']['value'])); ?>&nbsp;</td>
		<td><?php echo $signature['Signature']['to_ids'] ? 'Yes' : 'No';?>&nbsp;</td>
		<td class="actions" style="text-align:right;">	
			<?php 
			if ($signature['Event']['org'] == $me['org']) {
			    echo $this->Html->link(__('Edit', true), array('action' => 'edit', $signature['Signature']['id'])); 
			    echo $this->Html->link(__('Delete', true), array('action' => 'delete', $signature['Signature']['id']), null, sprintf(__('Are you sure you want to delete # %s?', true), $signature['Signature']['id'])); 
			} ?>
			<?php echo $this->Html->link(__('View', true), array('action' => 'view', $signature['Signature']['id'])); ?>
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
