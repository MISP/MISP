<div class="groups view">
<!--div class="actions" style="float:right;">
	<ul><li><?php echo $this->Html->link(__('Edit Profile', true), array('admin' => true, 'action' => 'edit', $group['Group']['id'])); ?> </li></ul>
</div-->
<h2><?php  echo __('Group');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo h($group['Group']['id']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Group'); ?></dt>
		<dd>
			<?php echo h($group['Group']['name']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Add'); ?></dt>
		<dd>
			<?php echo h($group['Group']['perm_add']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Modify'); ?></dt>
		<dd>
			<?php echo h($group['Group']['perm_modify']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Publish'); ?></dt>
		<dd>
			<?php echo h($group['Group']['perm_publish']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Full'); ?></dt>
		<dd>
			<?php echo h($group['Group']['perm_full']); ?>
			&nbsp;
		</dd>
	</dl>
</div>
<div class="actions">
	<h3><?php echo __('Actions'); ?></h3>
	<ul>
		<li><?php echo $this->Html->link(__('Edit Group'), array('admin' => true, 'action' => 'edit', $group['Group']['id'])); ?> </li>
		<li><?php echo $this->Form->postLink(__('Delete Group'), array('admin' => true, 'action' => 'delete', $group['Group']['id']), null, __('Are you sure you want to delete # %s?', $group['Group']['id'])); ?> </li>
		<li><?php echo $this->Html->link(__('List Groups'), array('admin' => true, 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link(__('New Group'), array('admin' => true, 'action' => 'add')); ?> </li>
	</ul>
</div>