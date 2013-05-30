<?php
$buttonAddStatus = $isAclAdd ? 'button_on':'button_off';
$mayModify = ($isAclModify || ($isAclModifyOrg && ($user['User']['org'] == $me['org'])));
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
?>
<div class="users view">
<div class="actions" style="float:right;">
	<ul><li><?php echo $this->Html->link(__('Edit Profile', true), array('admin' => true, 'action' => 'edit', $user['User']['id']), array('class' => $buttonModifyStatus)); ?> </li></ul>
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
		<dt><?php echo __('Role'); ?></dt>
		<dd>
			<?php echo $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Email'); ?></dt>
		<dd>
			<?php echo h($user['User']['email']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Autoalert'); ?></dt>
		<dd>
			<?php
				echo (h($user['User']['autoalert']) == 0)? 'No' : 'Yes'; ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Contactalert'); ?></dt>
		<dd>
			<?php echo h(0 == ($user['User']['contactalert'])) ? 'No' : 'Yes'; ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Authkey'); ?></dt>
		<dd>
			<?php echo h($user['User']['authkey']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Invited By'); ?></dt>
		<dd>
			<?php echo h($user2['User']['email']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Gpgkey'); ?></dt>
			<dd>
				<?php
if (h($user['User']['gpgkey']) != 0) {
						echo "<code>" . nl2br(h($user['User']['gpgkey'])) . "</code>";
} else {
						echo "N/A";
}?>
			</dd>
		<dt><?php echo __('Nids Sid'); ?></dt>
		<dd>
			<?php echo h($user['User']['nids_sid']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Termsaccepted'); ?></dt>
		<dd>
			<?php
if (h($user['User']['termsaccepted']) == 1) {
						echo "Yes";
} else {
						echo "No";
}?>
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
	<ul>
		<?php
if ($isAclModify): ?>
		<li><?php echo $this->Html->link(__('Edit User', true), array('admin' => 'true', 'action' => 'edit', $user['User']['id'])); ?></li>
		<li>&nbsp;</li>
		<?php
endif; ?>
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
			<td><?php echo h($event['id']);?></td>
			<td><?php echo h($event['org']);?></td>
			<td><?php echo h($event['date']);?></td>
			<td><?php echo h($event['risk']);?></td>
			<td><?php echo h($event['info']);?></td>
			<td><?php echo h($event['user_id']);?></td>
			<td><?php echo h($event['published']);?></td>
			<td><?php echo h($event['uuid']);?></td>
			<td class="actions">
				<?php echo $this->Html->link(__('Edit'), array('controller' => 'events', 'action' => 'edit', $event['id']), array('class' => $buttonModifyStatus)); ?>
				<?php
				if ($mayModify) echo $this->Form->postLink(__('Delete'), array('controller' => 'events', 'action' => 'delete', $event['id']), null, __('Are you sure you want to delete # %s?', $event['id']));
				else echo $this->Html->link(__('Delete'), array('controller' => 'events', 'action' => 'delete', $event['id']), array('class' => $buttonModifyStatus));
				?>
				<?php echo $this->Html->link(__('View'), array('controller' => 'events', 'action' => 'view', $event['id'])); ?>
			</td>
		</tr>
	<?php
	endforeach; ?>
	</table>
	<?php
endif; ?>

</div>