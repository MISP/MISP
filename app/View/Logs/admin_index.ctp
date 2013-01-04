<div class="logs index">
	<h2><?php echo __('Logs');?></h2>
		<?php
if ($isSearch == 1) {
	echo "<h4>Results for all log entries";
	if ($emailSearch != null) echo " for user \"<b>" . h($emailSearch) . "\"</b>";
	if ($orgSearch != null) echo " of the organisation \"<b>" . h($orgSearch) . "</b>\"";
	if ($actionSearch != "ALL") echo " of type \"<b>" . h($actionSearch) . "</b>\"";
	if ($titleSearch != null) echo " with the title \"<b>" . h($titleSearch) . "</b>\"";
	if ($changeSearch != null) echo " including the change \"<b>" . h($changeSearch) . "</b>\"";
	echo ":</h4>";
}
		?>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<!--th><?php echo $this->Paginator->sort('user_id');?></th-->
			<th><?php echo $this->Paginator->sort('email');?></th>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('created');?></th>
			<th><?php echo $this->Paginator->sort('action');?></th>
			<th><?php echo $this->Paginator->sort('title');?></th>
			<th><?php echo $this->Paginator->sort('change');?></th>
	</tr><?php
foreach ($list as $item): ?>
	<tr>
		<td class="short"><?php echo h($item['Log']['id']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Log']['email']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Log']['org']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Log']['created']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Log']['action']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Log']['title']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Log']['change']); ?>&nbsp;</td>
	</tr><?php
endforeach; ?>
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
