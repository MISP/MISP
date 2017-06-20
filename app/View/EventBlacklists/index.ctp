<div class="eventBlacklists index">
	<h2><?php echo __('Event Blacklists');?></h2>
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
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('event_uuid');?></th>
			<th><?php echo $this->Paginator->sort('created');?></th>
			<th><?php echo $this->Paginator->sort('event_info');?></th>
			<th><?php echo $this->Paginator->sort('comment');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($response as $item): ?>
	<tr>
		<td class="short"><?php echo h($item['EventBlacklist']['id']); ?>&nbsp;</td>
		<td class="short"><?php echo (isset($item['EventBlacklist']['event_orgc']) ? h($item['EventBlacklist']['event_orgc']) : '&nbsp;'); ?></td>
		<td class="short"><?php echo h($item['EventBlacklist']['event_uuid']); ?>&nbsp;</td>
		<td><?php echo h($item['EventBlacklist']['created']); ?>&nbsp;</td>
		<td class="short"><?php echo (isset($item['EventBlacklist']['event_info']) ? h($item['EventBlacklist']['event_info']) : '&nbsp;'); ?></td>
		<td class="short"><?php echo (isset($item['EventBlacklist']['comment']) ? h($item['EventBlacklist']['comment']) : '&nbsp;'); ?></td>
		<td class="short action-links">
			<a href="<?php echo $baseurl;?>/eventBlacklists/edit/<?php echo h($item['EventBlacklist']['id']); ?>"><span class="icon-edit" title="edit" role="button" tabindex="0" aria-label="Edit blacklist entry">&nbsp;</span></a>
			<?php echo $this->Form->postLink('', array('action' => 'delete', h($item['EventBlacklist']['id'])), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete the blacklist entry for the event UUID %s?', h($item['EventBlacklist']['event_uuid']))); ?>
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
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'eventBlacklists'));
?>
