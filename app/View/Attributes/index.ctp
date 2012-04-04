<div class="attributes index">
	<h2><?php echo __('Attributes');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('event_id');?></th>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th>IDS Signature</th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($attributes as $attribute): ?>
	<tr>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true) ;?>';">
			<?php echo $this->Html->link($attribute['Event']['id'], array('controller' => 'events', 'action' => 'view', $attribute['Event']['id'])); ?>
		</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true) ;?>';">
		<?php echo h($attribute['Attribute']['category']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true) ;?>';">
		<?php echo h($attribute['Attribute']['type']); ?>&nbsp;</td>
		<td onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true) ;?>';">
		<?php
		$sig_display = nl2br(Sanitize::html($attribute['Attribute']['value']));
		if('attachment' == $attribute['Attribute']['type'] ||
		   'malware-sample' == $attribute['Attribute']['type']) {
		    echo $this->Html->link($sig_display, array('controller' => 'attributes', 'action' => 'download', $attribute['Attribute']['id']));
		} elseif('link' == $attribute['Attribute']['type']) {
			?><A HREF="<?php echo $attribute['Attribute']['value']?>"><?php echo $attribute['Attribute']['value']?></A><?php	
		} else {
			echo $sig_display;
		}
		?>&nbsp;</td>
		<td class="short" style="text-align: center;" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true) ;?>';">
		<?php echo $attribute['Attribute']['to_ids'] ? 'Yes' : 'No'; ?>&nbsp;</td>
		<td class="actions"><?php
			if ($isAdmin || $attribute['Event']['org'] == $me['org']) {
				echo $this->Html->link(__('Edit'), array('action' => 'edit', $attribute['Attribute']['id']));
				echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $attribute['Attribute']['id']), null, __('Are you sure you want to delete this attribute?'));
			}
			echo $this->Html->link(__('View'), array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']));
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
