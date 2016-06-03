<div class="users view">
<h2><?php  echo __('User');?></h2>
	<dl style="width:700px;">
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
			<?php echo h($user['Organisation']['name']); ?>
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
			<?php
				echo h($user['User']['authkey']);
				if (!Configure::read('MISP.disableUserSelfManagement') || $isAdmin) {
					echo '(' . $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', $user['User']['id'])) . ')';
				}
			?>
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
		<dt><?php echo __('PGP key'); ?></dt>
		<dd class="red">
			<?php echo (h($user['User']['gpgkey'])) ? $this->Utility->space2nbsp(nl2br(h($user['User']['gpgkey']))) : "N/A"; ?>
		</dd>
		<?php if (Configure::read('SMIME.enabled')): ?>
			<dt><?php echo __('SMIME Public certificate'); ?></dt>
			<dd class="red">
				<?php echo (h($user['User']['certif_public'])) ? $this->Utility->space2nbsp(nl2br(h($user['User']['certif_public']))) : "N/A"; ?>
			</dd>
		<?php endif; ?>
	</dl>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'));
?>
