<div class="roles view">
<h2><?php  echo __('Role');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo $role['Role']['id']; ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Name'); ?></dt>
		<dd>
			<?php echo h($role['Role']['name']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Add'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_add']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Modify'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_modify']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Publish'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_publish']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Auth'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_auth']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Regexp'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_regexp_access']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Admin'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_admin']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Site Admin'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_site_admin']); ?>
			&nbsp;
		</dd>
	</dl>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'roles'));
?>