<div class="whitelists view">
<h2><?php  echo __('Whitelist');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo h($whitelist['Whitelist']['id']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Name'); ?></dt>
		<dd>
			<?php echo h($whitelist['Whitelist']['name']); ?>
			&nbsp;
		</dd>
	</dl>
</div>
<div class="actions">
	<h3><?php echo __('Actions'); ?></h3>
	<ul>
		<li><?php echo $this->Html->link(__('Edit Whitelist'), array('admin' => true, 'action' => 'edit', $whitelist['Whitelist']['id'])); ?> </li>
		<li><?php echo $this->Form->postLink(__('Delete Whitelist'), array('admin' => true, 'action' => 'delete', $whitelist['Whitelist']['id']), null, __('Are you sure you want to delete # %s?', $whitelist['Whitelist']['id'])); ?> </li>
		<li><?php echo $this->Html->link(__('List Whitelists'), array('admin' => true, 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link(__('New Whitelist'), array('admin' => true, 'action' => 'add')); ?> </li>
	</ul>
</div>