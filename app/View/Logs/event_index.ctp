<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id']));
$mayPublish = ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id']);
?>
<div class="logs index">
<h2>Logs</h2>
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
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('email');?></th>
			<th><?php echo $this->Paginator->sort('action');?></th>
			<th><?php echo $this->Paginator->sort('model');?></th>
			<th><?php echo $this->Paginator->sort('title');?></th>
			<th><?php echo $this->Paginator->sort('created');?></th>
		</tr>
		<?php foreach ($list as $item): ?>
		<tr>
			<td class="short">
			<?php
				$imgRelativePath = 'orgs' . DS . h($item['Log']['org']) . '.png';
				$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
				if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($item['Log']['org']) . '.png', array('alt' => h($item['Log']['org']), 'title' => h($item['Log']['org']), 'style' => 'width:24px; height:24px'));
				else echo $this->Html->tag('span', h($item['Log']['org']), array('class' => 'welcome', 'style' => 'float:left;'));
			?>
			&nbsp;
			</td>
			<td class="short"><?php echo h($item['Log']['email']); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Log']['action']); ?>&nbsp;</td>
			<td class="short"><?php
				if ($item['Log']['model'] !== 'ShadowAttribute') echo h($item['Log']['model']);
				else echo 'Proposal';
			?>&nbsp;</td>
			<td><?php echo h($item['Log']['title']); ?>&nbsp;</td>
			<td class="short"><?php echo (h($item['Log']['created'])); ?>&nbsp;</td>
		</tr>
		<?php endforeach; ?>
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
	// We mimic the $event from some other views to pass the ID back to the sidemenu
	$event['Event']['id'] = $eventId;
	echo $this->element('side_menu', array('menuList' => 'event', 'event' => $event, 'menuItem' => 'eventLog', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>
