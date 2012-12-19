<div class="logs index">
	<h2><?php echo __('Logs');?></h2>
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
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($logs as $log): ?>
	<tr>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['id']); ?>&nbsp;</td>
		<!--td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['user_id']); ?>&nbsp;</td-->
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['email']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['org']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['created']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['action']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['title']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $log['Log']['id']), true);?>';">
		<?php echo h($log['Log']['change']); ?>&nbsp;</td>
		<td class="actions">
			<?php echo $this->Html->link(__('View'), array('admin' => true, 'action' => 'view', $log['Log']['id'])); ?>
		</td>
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
