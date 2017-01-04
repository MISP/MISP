<div class="roles view">
<h2><?php echo __('Role');?></h2>
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
		<dt><?php echo __('Permission level'); ?></dt>
		<dd>
			<?php
				echo h($premissionLevelName[$role['Role']['permission']]);
			?>
			&nbsp;
		</dd>
		<?php
		foreach ($role['Role'] as $k => $item):
			if (substr($k, 0, 5) === 'perm_' && !in_array($k, array('perm_add', 'perm_modify', 'perm_modify_org', 'perm_publish', 'perm_full'))):
				$nameParts = explode('_', $k);
				unset($nameParts[0]);
				foreach ($nameParts as &$p) $p = ucfirst($p);
				$name = implode(' ', $nameParts);
				?>
					<dt><?php echo __($name); ?></dt>
					<dd class="<?php echo $role['Role'][$k] ? 'green' : 'red';?>">
						<?php echo $role['Role'][$k] ? 'Yes' : 'No'; ?>
						&nbsp;
					</dd>
				<?php
			endif;

		endforeach;

		?>
	</dl>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'roles'));
?>
