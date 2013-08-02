<?php
$buttonAddStatus = $isAclAdd ? 'button_on':'button_off';
$mayModify = ($isSiteAdmin || ($isAdmin && ($user['User']['org'] == $me['org'])));
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
?>
<div class="users view">
<h2><?php  echo __('User');?></h2>
	<dl style="width:600px;">
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo h($user['User']['id']); ?>
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
			(<?php echo $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', $user['User']['id']));?>)
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
				<dt><?php echo __('Password change'); ?></dt>
		<dd>
			<?php
if (h($user['User']['change_pw']) == 1) {
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
	<br />
	<div class="related table table-striped table-condensed">
		<h3><?php echo __('Related Events');?></h3>
		<?php if (!empty($user['Event'])):?>
		<table>
		<tr>
			<th><?php echo __('Published'); ?></th>
			<th><?php echo __('Id'); ?></th>
			<th><?php echo __('Date'); ?></th>
			<th><?php echo __('Risk'); ?></th>
			<th><?php echo __('Info'); ?></th>
			<th><?php echo __('Uuid'); ?></th>
			<th><?php echo __('Distribution'); ?></th>
			<th class="actions"><?php echo __('Actions');?></th>
		</tr>
		<?php
		$i = 0;
		foreach ($user['Event'] as $event): ?>
		<tr>
				<td>
					<div class='<?php echo ($event['published'] == 1) ? 'icon-ok' : 'icon-remove';; ?>'></div>
				</td>
				<td><?php echo h($event['id']);?></td>
				<td><?php echo h($event['date']);?></td>
				<td><?php echo h($event['risk']);?></td>
				<td><?php echo h($event['info']);?></td>
				<td><?php echo h($event['uuid']);?></td>
				<td><?php echo h($event['distribution']);?></td>
				<td class="short action-links">
					<?php if ($mayModify) echo $this->Html->link('', array('controller' => 'events', 'action' => 'edit', $event['id']), array('class' => 'icon-download-alt')); ?>
					<?php
					if ($mayModify) echo $this->Form->postLink('', array('controller' => 'events', 'action' => 'delete', $event['id']), array('class' => 'icon-trash'), __('Are you sure you want to delete # %s?', $event['id']));
					?>
					<?php echo $this->Html->link('', array('controller' => 'events', 'action' => 'view', $event['id']), array('class' => 'icon-list-alt')); ?>
				</td>
			</tr>
		<?php
		endforeach; ?>
		</table>
		<?php
	endif; ?>
	</div>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('Edit User', array('admin' => true, 'action' => 'edit', $user['User']['id'])); ?></li>
		<li class="divider"></li>
		<li class="active"><?php echo $this->Html->link('New User', array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link('List Users', array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
		<li class="divider"></li>
		<?php if ($isSiteAdmin): ?>
		<li><?php echo $this->Html->link('New Role', array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
		<?php endif; ?>
		<li><?php echo $this->Html->link('List Roles', array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
		<?php if ($isSiteAdmin): ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Contact users', array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
		<?php endif; ?>
	</ul>
</div>