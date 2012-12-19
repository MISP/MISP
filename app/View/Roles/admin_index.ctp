<div class="roles index">
	<h2><?php echo __('Roles');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th><?php echo $this->Paginator->sort('permission', 'Permission');?></th>
			<th><?php echo $this->Paginator->sort('perm_sync', 'Sync Actions');?></th>
			<th><?php echo $this->Paginator->sort('perm_admin', 'Administration Actions');?></th>
			<th><?php echo $this->Paginator->sort('perm_audit', 'Audit Actions');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($roles as $role): ?>
	<tr>
		<td class="short"><?php echo h($role['Role']['id']); ?>&nbsp;</td>
		<td class="short"><?php echo h($role['Role']['name']); ?>&nbsp;</td>
		<td class="short"><?php echo h($options[$role['Role']['permission']]); ?>&nbsp;</td>
		<td class="short"><?php echo h($role['Role']['perm_sync']); ?>&nbsp;</td>
		<td class="short"><?php echo h($role['Role']['perm_admin']); ?>&nbsp;</td>
		<td class="short"><?php echo h($role['Role']['perm_audit']); ?>&nbsp;</td>
		<td class="actions">
			<?php echo $this->Html->link(__('Edit'), array('admin' => true, 'action' => 'edit', $role['Role']['id'])); ?>
			<?php echo $this->Form->postLink(__('Delete'), array('admin' => true, 'action' => 'delete', $role['Role']['id']), null, __('Are you sure you want to delete # %s?', $role['Role']['id'])); ?>
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