<div class="orgBlacklists index">
	<h2><?php echo __('Organisation Blacklists');?></h2>
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
			<th><?php echo $this->Paginator->sort('org_name');?></th>
			<th><?php echo $this->Paginator->sort('org_uuid');?></th>
			<th><?php echo $this->Paginator->sort('created');?></th>
			<th><?php echo $this->Paginator->sort('comment');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($response as $item): ?>
	<tr>
		<td class="short"><?php echo h($item['OrgBlacklist']['id']); ?>&nbsp;</td>
		<td class="short"><?php echo (isset($item['OrgBlacklist']['org_name']) ? h($item['OrgBlacklist']['org_name']) : '&nbsp;'); ?></td>
		<td class="short"><?php echo h($item['OrgBlacklist']['org_uuid']); ?>&nbsp;</td>
		<td><?php echo h($item['OrgBlacklist']['created']); ?>&nbsp;</td>
		<td class="short"><?php echo (isset($item['OrgBlacklist']['comment']) ? h($item['OrgBlacklist']['comment']) : '&nbsp;'); ?></td>
		<td class="short action-links">
			<a href="<?php echo $baseurl;?>/orgBlacklists/edit/<?php echo h($item['OrgBlacklist']['id']); ?>"><span class="icon-edit" title="edit">&nbsp;</span></a>
			<?php echo $this->Form->postLink('', array('action' => 'delete', h($item['OrgBlacklist']['id'])), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete the blacklist entry for the event UUID %s?', h($item['OrgBlacklist']['org_uuid']))); ?>
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
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'orgBlacklists'));
