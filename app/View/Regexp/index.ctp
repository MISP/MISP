<div class="regexp index">
	<h2><?php echo __('Import Regexp');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('regexp');?></th>
			<th><?php echo $this->Paginator->sort('replacement');?></th>
	</tr><?php
foreach ($list as $item):?>
	<tr>
		<td class="short"><?php echo h($item['Regexp']['id']);?>&nbsp;</td>
		<td class="short"><?php echo h($item['Regexp']['regexp']);?>&nbsp;</td>
		<td class="short"><?php echo h($item['Regexp']['replacement']);?>&nbsp;</td>
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
