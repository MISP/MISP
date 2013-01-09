<div class="whitelist index">
	<h2><?php echo __('Import Blacklist');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($list as $item):?>
	<tr>
		<td class="short"><?php echo h($item['Blacklist']['id']);?>&nbsp;</td>
		<td class="short"><?php echo h($item['Blacklist']['name']);?>&nbsp;</td>
		<td class="actions">
			<?php echo $this->Html->link(__('Edit'), array('admin' => true, 'action' => 'edit', $item['Blacklist']['id']));?>
			<?php echo $this->Form->postLink(__('Delete'), array('admin' => true, 'action' => 'delete', $item['Blacklist']['id']), null, __('Are you sure you want to delete "%s"?', $item['Blacklist']['name']));?>
		</td>
	</tr><?php
endforeach;?>
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

		<li><?php echo $this->Html->link(__('New Blacklist'), array('admin' => true, 'action' => 'add'));?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu');?>
	</ul>
</div>