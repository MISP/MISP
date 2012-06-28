<div class="groups view">
<h2><?php  echo __('Group');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo h($group['Group']['id']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Name'); ?></dt>
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
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>