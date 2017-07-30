<div class="threads index">
	<h2>Discussions</h2>
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
			<th>Title</th>
			<th><?php echo $this->Paginator->sort('date_modified', 'Last Post On');?></th>
			<th>Last Post By</th>
			<th><?php echo $this->Paginator->sort('date_created', 'Thread started On');?></th>
			<th>Posts</th>
			<th>Distribution</th>
			<th>Actions</th>
	</tr>
	<?php
	$url = Configure::read('MISP.baseurl');
foreach ($threads as $thread):
	$lastPost = end($thread['Post']);
	?>

		<tr>
			<td class="short" style="text-align: left;" ondblclick="document.location.href ='<?php echo $url;?>/threads/view/<?php echo $thread['Thread']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($thread['Organisation']['name']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($thread['Organisation']['name']) . '.png', array('alt' => h($thread['Organisation']['name']), 'title' => h($thread['Organisation']['name']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($thread['Organisation']['name']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				&nbsp;
			</td>
			<td ondblclick="document.location.href ='<?php echo $url;?>/threads/view/<?php echo $thread['Thread']['id'];?>'">
				<?php
					echo h($thread['Thread']['title']);
				?>
			</td>
			<td class="short" style="text-align: center;" ondblclick="document.location.href ='<?php echo $url;?>/threads/view/<?php echo $thread['Thread']['id'];?>'">
				<?php
					echo h($thread['Thread']['date_modified']);
				?>
				&nbsp;
			</td>
			<td class="short" style="text-align: center;" ondblclick="document.location.href ='<?php echo $url;?>/threads/view/<?php echo $thread['Thread']['id'];?>'">
				<?php
					echo isset($lastPost['User']['email']) ? h($lastPost['User']['email']) : '';
				?>
				&nbsp;
			</td>
			<td class="short" style="text-align: center;" ondblclick="document.location.href ='<?php echo $url;?>/threads/view/<?php echo $thread['Thread']['id'];?>'">
				<?php
					echo h($thread['Thread']['date_created']);
				?>
			</td>
			<td class="short" ondblclick="document.location.href ='<?php echo $url;?>/threads/view/<?php echo $thread['Thread']['id'];?>'">
				<?php
					echo h($thread['Thread']['post_count']);
				?>
			</td>
			<td class="short" ondblclick="document.location.href ='<?php echo $url;?>/threads/view/<?php echo $thread['Thread']['id'];?>'">
				<?php
					if ($thread['Thread']['distribution'] < 4) echo $distributionLevels[$thread['Thread']['distribution']];
					else echo '<a href="/sharing_groups/view/' . h($thread['Thread']['sharing_group_id']) . '" title="' . h($thread['SharingGroup']['name']) . '">Sharing group</a>';
				?>
			</td>
			<td class="short action-links">
				<?php
					echo $this->Html->link('', array('action' => 'view', $thread['Thread']['id']), array('class' => 'icon-list-alt', 'title' => 'View Discussion'));
				?>
			</td>
		</tr>
	<?php
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
	echo $this->element('side_menu', array('menuList' => 'threads', 'menuItem' => 'index'));
