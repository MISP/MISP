<div class="users view">
<h2><?php  echo __('User');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo h($user['User']['id']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Email'); ?></dt>
		<dd>
			<?php echo h($user['User']['email']); ?>
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
		<dt><?php echo __('Autoalert'); ?></dt>
		<dd>
			<?php echo h(0 == ($user['User']['autoalert'])) ? 'No' : 'Yes'; ?>
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
		<dt><?php echo __('NIDS Start SID'); ?></dt>
		<dd>
			<?php echo h($user['User']['nids_sid']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Termsaccepted'); ?></dt>
		<dd>
			<?php echo h((0 == $user['User']['termsaccepted'])? 'No' : 'Yes'); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('GPG Key'); ?></dt>
		<dd>
		<?php
if (!empty($user['User']['gpgkey'])) {
	echo "<code>" . nl2br(h($user['User']['gpgkey'])) . "</code>";
} else {
	echo "N/A";
}
		?>
			&nbsp;
		</dd>
	</dl>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'));
?>

