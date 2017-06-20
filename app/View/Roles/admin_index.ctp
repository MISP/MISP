<div class="roles index">
	<h2><?php echo __('Roles');?></h2>
	<div class="pagination">
		<ul>
		<?php
			$this->Paginator->options(array(
				'update' => '.span12',
				'evalScripts' => true,
				'before' => '$(".progress").show()',
				'complete' => '$(".progress").hide()',
			));

			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th>Default</th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th><?php echo $this->Paginator->sort('permission', 'Permission');?></th>
			<?php
				foreach ($permFlags as $k => $flags):
			?>
				<th><?php echo $this->Paginator->sort($k, $flags['text']);?></th>
			<?php
				endforeach;
			?>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($list as $item): ?>
	<tr>
		<td><?php echo $this->Html->link(h($item['Role']['id']), array('admin' => true, 'action' => 'edit', $item['Role']['id'])); ?>&nbsp;</td>
		<td class="short" style="text-align:center;width:20px;"><input class="servers_default_role_checkbox" type="checkbox" data-id="<?php echo h($item['Role']['id']); ?>" <?php if ($default_role_id && $default_role_id == $item['Role']['id']) echo 'checked'; ?>></td>
		<td><?php echo h($item['Role']['name']); ?>&nbsp;</td>
		<td><?php echo h($options[$item['Role']['permission']]); ?>&nbsp;</td>
		<?php foreach ($permFlags as $k => $flags): ?>
			<td class="short"><span class="<?php if ($item['Role'][$k]) echo 'icon-ok'; ?>"></span>&nbsp;</td>
		<?php endforeach; ?>
		<td class="short action-links">
			<?php echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $item['Role']['id']), array('class' => 'icon-edit', 'title' => 'Edit')); ?>
			<?php echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $item['Role']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete %s?', $item['Role']['name'])); ?>
		</td>
	</tr><?php
endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	));
	?>
	</p>
	<div class="pagination">
		<ul>
		<?php
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'indexRole'));
