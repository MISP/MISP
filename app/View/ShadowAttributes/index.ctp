<div class="shadowAttributes index">
	<h2>Proposals</h2>
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

	<div class="tabMenuFixedContainer" style="display:<?php echo !$all ? 'none' : 'block';?>;">
		<span class="tabMenuFixed tabMenuSides useCursorPointer " style="margin-left:50px;">
			<span role="button" tabindex="0" aria-label="Only list proposals of my organisation" title="Only list proposals of my organisation" class="" onclick="window.location.href='<?php echo $baseurl; ?>/shadow_attributes/index'">My Org's Events</span>
		</span>
	</div>
	<div class="tabMenuFixedContainer" style="display:<?php echo $all ? 'none' : 'block';?>;">
		<span class="tabMenuFixed tabMenuSides useCursorPointer " style="margin-left:50px;">
			<span role="button" tabindex="0" aria-label="List all proposals" title="List all proposals" onclick="window.location.href='<?php echo $baseurl; ?>/shadow_attributes/index/all:1'">All Events</span>
		</span>
	</div>
	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th>Event</th>
			<th>
				<?php echo $this->Paginator->sort('org', 'Proposal by');?>
			</th>
			<th>
				Type
			</th>
			<th>
				<?php echo $this->Paginator->sort('Event.Orgc.name', 'Event creator');?>
			</th>
			<th>
				<?php echo $this->Paginator->sort('id', 'Event Info');?>
			</th>
			<th>
				<?php echo $this->Paginator->sort('value', 'Proposed value');?>
			</th>
			<th>
				<?php echo $this->Paginator->sort('category', 'Category');?>
			</th>
			<th>
				<?php echo $this->Paginator->sort('type', 'Type');?>
			</th>
			<th>
				<?php echo $this->Paginator->sort('timestamp', 'Created');?>
			</th>
		</tr>
		<?php foreach ($shadowAttributes as $event):?>
		<tr>
			<td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo h($event['Event']['id']);?>
			</td>
			<td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($event['Org']['name']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Org']['name']) . '.png', array('title' => h($event['Org']['name']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($event['Org']['name']), array('style' => 'float:left;'));
				?>
				&nbsp;
			</td>
			<td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php
					if ($event['ShadowAttribute']['old_id'] != 0) {
						echo 'Attribute edit';
					} else {
						echo 'New Attribute';
					}
				?>
			</td>
			<td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo h($event['Event']['Orgc']['name']); ?>
			</td>
			<td onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo h($event['Event']['info']); ?>
			</td>
			<td onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo h($event['ShadowAttribute']['value']);?>
			</td>
			<td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo h($event['ShadowAttribute']['category']);?>
			</td>
			<td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo h($event['ShadowAttribute']['type']);?>
			</td>
			<td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo date('Y-m-d H:i:s', $event['ShadowAttribute']['timestamp']);?>
			</td>
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
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewProposals'));
?>
