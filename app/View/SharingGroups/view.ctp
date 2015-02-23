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
		<dt><?php echo __('Description'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_add']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Members'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_add']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Pushable'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_modify']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Extendable'); ?></dt>
		<dd>
			<?php echo h($role['Role']['perm_publish']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Active'); ?></dt>
	</dl>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'roles'));
?>