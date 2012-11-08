<?php
$mayAdd = $isAclAdd;
$buttonAddStatus = $mayAdd ? 'button_on':'button_off';
$mayModify = ($isAclModify || $isAclModifyOrg);
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
?>
<div class="servers index">
	<h2><?php echo __('Servers');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('push');?></th>
			<th><?php echo $this->Paginator->sort('pull');?></th>
			<th><?php echo $this->Paginator->sort('url');?></th>
			<th>From</th>
			<?php if ($isAdmin): ?>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<?php endif; ?>
			<th>Last Pulled ID</th>
			<th>Last Pushed ID</th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($servers as $server): ?>
	<tr>
		<td class="short" style="text-align: center;"><?php echo ($server['Server']['push'])? 'Yes' : 'No'; ?>&nbsp;</td>
		<td class="short" style="text-align: center;"><?php echo ($server['Server']['pull'])? 'Yes' : 'No'; ?>&nbsp;</td>
		<td><?php echo h($server['Server']['url']); ?>&nbsp;</td>
		<td><?php echo h($server['Server']['organization']); ?>&nbsp;</td>
		<?php if ($isAdmin): ?>
		<td class="short"><?php echo h($server['Server']['org']); ?>&nbsp;</td>
		<?php endif; ?>
		<td class="short"><?php echo $server['Server']['lastpulledid']; ?></td>
		<td class="short"><?php echo $server['Server']['lastpushedid']; ?></td>
		<td class="actions">
			<?php echo $this->Html->link(__('Edit'), array('action' => 'edit', $server['Server']['id']), $isAclModify || ($isAclModifyOrg && $server['Server']['org'] == $me['org']) ? null : array('class' => $buttonModifyStatus)); ?>
			<?php if ($mayModify || $server['Server']['org'] == $me['org']) echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $server['Server']['id']), null, __('Are you sure you want to delete # %s?', $server['Server']['id']));
			else echo $this->Html->link(__('Delete'), array('action' => 'delete', $server['Server']['id']), array('class' => $buttonModifyStatus)); ?>

			<?php // if ($server['Server']['pull']) echo $this->Form->postLink(__('Pull'), array('action' => 'pull', $server['Server']['id']) ); ?>
			<?php // if ($server['Server']['push']) echo $this->Form->postLink(__('Push'), array('action' => 'push', $server['Server']['id']) ); ?>

			<?php if ($server['Server']['pull']) echo $this->Form->postLink(__('Pull All'), array('action' => 'pull', $server['Server']['id'], 'full') ); ?>
			<?php if ($server['Server']['push']) echo $this->Form->postLink(__('Push All'), array('action' => 'push', $server['Server']['id'], 'full') ); ?>
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
		<li><?php echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add'), array('class' => $buttonAddStatus)); ?></li>
		<li><?php echo $this->Html->link(__('List Servers'), array('controller' => 'servers', 'action' => 'index'));?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
