<div class="logs view">
<!--div class="actions" style="float:right;">
	<ul><li><?php echo $this->Html->link(__('Edit Profile', true), array('admin' => true, 'action' => 'edit', $log['Log']['id'])); ?> </li></ul>
</div-->
<h2><?php  echo __('Log');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo h($log['Log']['id']); ?>
			&nbsp;
		</dd>
		<!--dt><?php echo __('User'); ?></dt>
		<dd>
			<?php echo h($log['Log']['user_id']); ?>
			&nbsp;
		</dd-->
		<dt><?php echo __('Org'); ?></dt>
		<dd>
			<?php echo h($log['Log']['org']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Email'); ?></dt>
		<dd>
			<?php echo h($log['Log']['email']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Date'); ?></dt>
		<dd>
			<?php echo h($log['Log']['created']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Action'); ?></dt>
		<dd>
			<?php echo h($log['Log']['action']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Title'); ?></dt>
		<dd>
			<?php echo h($log['Log']['title']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Change'); ?></dt>
		<dd>
			<?php echo h($log['Log']['change']); ?>
			&nbsp;
		</dd>
	</dl>
</div>
<div class="actions">
	<h3><?php echo __('Actions'); ?></h3>
	<ul>
		<li><?php echo $this->Html->link(__('List Logs'), array('admin' => true, 'action' => 'index')); ?> </li>
	</ul>
</div>