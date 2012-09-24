<?php
$buttonAddStatus = $isAclAdd ? 'button_on':'button_off';
$mayModify = $isAclModify || ($user['User']['org'] == $me['org']);
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
$buttonCounter = 0;
?>
<div class="users view">
<div class="actions" style="float:right;">
	<ul><li><?php echo $this->Html->link(__('Edit Profile', true), array('admin' => true, 'action' => 'edit', $user['User']['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus)); ?> </li></ul>
</div>
<h2><?php  echo __('User');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo h($user['User']['id']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Password'); ?></dt>
		<dd>
			<?php echo h($user['User']['password']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Org'); ?></dt>
		<dd>
			<?php echo h($user['User']['org']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Group'); ?></dt>
		<dd>
			<?php echo $this->Html->link($user['Group']['name'], array('controller' => 'groups', 'action' => 'view', $user['Group']['id'])); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Email'); ?></dt>
		<dd>
			<?php echo h($user['User']['email']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Autoalert'); ?></dt>
		<dd>
			<?php echo h($user['User']['autoalert']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Authkey'); ?></dt>
		<dd>
			<?php echo h($user['User']['authkey']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Invited By'); ?></dt>
		<dd>
			<?php echo h($user['User']['invited_by']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Gpgkey'); ?></dt>

				<dd style="font-size: 10px; line-height:100%;">
						<code><?php echo nl2br(h($user['User']['gpgkey'])); ?></code>
						&nbsp;
				</dd>

		<dt><?php echo __('Nids Sid'); ?></dt>
		<dd>
			<?php echo h($user['User']['nids_sid']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Termsaccepted'); ?></dt>
		<dd>
			<?php echo h($user['User']['termsaccepted']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Newsread'); ?></dt>
		<dd>
			<?php echo h($user['User']['newsread']); ?>
			&nbsp;
		</dd>
	</dl>
</div>
<div class="actions">
	<h3><?php echo __('Actions'); ?></h3>
	<ul>
		<li><?php echo $this->Html->link(__('Edit User'), array('admin' => true, 'action' => 'edit', $user['User']['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus)); ?> </li>
		<li><?php
		if ($mayModify) echo $this->Form->postLink(__('Delete User'), array('admin' => true, 'action' => 'delete', $user['User']['id']), null, __('Are you sure you want to delete # %s?', $user['User']['id']));
		else echo $this->Html->link(__('Delete User'), array('admin' => true, 'action' => 'delete', $user['User']['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus));
		?> </li>
		<li><?php echo $this->Html->link(__('List Users'), array('admin' => true, 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link(__('New User'), array('admin' => true, 'action' => 'add'), array('id' => $buttonAddStatus, 'class' => $buttonAddStatus, 'disabled' => 'disabled', 'readonly' => 'readonly')); ?> </li>
		<li><?php echo $this->Html->link(__('List Events'), array('controller' => 'events', 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link(__('New Event'), array('controller' => 'events', 'action' => 'add'), array('id' => $buttonAddStatus, 'class' => $buttonAddStatus, 'disabled' => 'disabled', 'readonly' => 'readonly')); ?> </li>
	</ul>
</div>
<div class="related">
	<h3><?php echo __('Related Events');?></h3>
	<?php if (!empty($user['Event'])):?>
	<table cellpadding = "0" cellspacing = "0">
	<tr>
		<th><?php echo __('Id'); ?></th>
		<th><?php echo __('Org'); ?></th>
		<th><?php echo __('Date'); ?></th>
		<th><?php echo __('Risk'); ?></th>
		<th><?php echo __('Info'); ?></th>
		<th><?php echo __('User Id'); ?></th>
		<th><?php echo __('Published'); ?></th>
		<th><?php echo __('Uuid'); ?></th>
		<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
		$i = 0;
		foreach ($user['Event'] as $event): ?>
		<tr>
			<td><?php echo $event['id'];?></td>
			<td><?php echo $event['org'];?></td>
			<td><?php echo $event['date'];?></td>
			<td><?php echo $event['risk'];?></td>
			<td><?php echo $event['info'];?></td>
			<td><?php echo $event['user_id'];?></td>
			<td><?php echo $event['published'];?></td>
			<td><?php echo $event['uuid'];?></td>
			<td class="actions">
				<?php echo $this->Html->link(__('View'), array('controller' => 'events', 'action' => 'view', $event['id'])); ?>
				<?php echo $this->Html->link(__('Edit'), array('controller' => 'events', 'action' => 'edit', $event['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus)); ?>
				<?php
				if ($mayModify) echo $this->Form->postLink(__('Delete'), array('controller' => 'events', 'action' => 'delete', $event['id']), null, __('Are you sure you want to delete # %s?', $event['id']));
				else echo $this->Html->link(__('Delete'), array('controller' => 'events', 'action' => 'delete', $event['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus));
				?>
			</td>
		</tr>
	<?php endforeach; ?>
	</table>
<?php endif; ?>

</div>
