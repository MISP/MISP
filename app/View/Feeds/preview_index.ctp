<div class="events index">
<h4 class="visibleDL notPublished" >You are currently viewing the event index of a feed (<?php echo h($feed['Feed']['name']); ?> by <?php echo h($feed['Feed']['provider']); ?>).</h4>
	<div class="pagination">
		<ul>
		<?php
			$eventViewURL = '/feeds/previewEvent/' . h($id) . '/';
			$this->Paginator->options(array(
				'url' => $id,
				'update' => '.span12',
				'evalScripts' => true,
				'before' => '$(".progress").show()',
				'complete' => '$(".progress").hide()',
			));
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>
	<?php
		$tab = "Center";
		$filtered = false;
		if (count($passedArgsArray) > 0) {
			$tab = "Left";
			$filtered = true;
		}
	?>

	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th class="filter"><?php echo $this->Paginator->sort('Org', 'org'); ?></th>
			<th class="filter">Tags</th>
			<th class="filter"><?php echo $this->Paginator->sort('date');?></th>
			<th class="filter" title="<?php echo $eventDescriptions['threat_level_id']['desc'];?>"><?php echo $this->Paginator->sort('threat_level_id');?></th>
			<th class="filter" title="<?php echo $eventDescriptions['analysis']['desc']; ?>"><?php echo $this->Paginator->sort('analysis');?></th>
			<th class="filter"><?php echo $this->Paginator->sort('info');?></th>
			<th class="filter"><?php echo $this->Paginator->sort('timestamp');?></th>
			<th class="actions">Actions</th>

		</tr>
		<?php if (!empty($events)) foreach ($events as $uuid => $event): ?>
		<tr>
			<td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($uuid);?>'"><?php echo h($event['Orgc']['name']); ?></td>
			<td style = "max-width: 200px;width:10px;">
				<?php foreach ($event['Tag'] as $tag): ?>
					<span class=tag style="margin-bottom:3px;background-color:<?php echo isset($tag['colour']) ? h($tag['colour']) : 'red';?>;color:<?php echo $this->TextColour->getTextColour(isset($tag['colour']) ? h($tag['colour']) : 'red');?>;" title="<?php echo h($tag['name']); ?>"><?php echo h($tag['name']); ?></span>
				<?php endforeach; ?>
			</td>
			<td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($uuid);?>'">
				<?php echo h($event['date']); ?>&nbsp;
			</td>
			<td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($uuid);?>'">
				<?php
					echo h($threatLevels[isset($event['threat_level_id']) ? $event['threat_level_id'] : (Configure::read('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : 4)]);
				?>
			</td>
			<td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($uuid);?>'">
				<?php echo $analysisLevels[$event['analysis']]; ?>&nbsp;
			</td>
			<td ondblclick="document.location.href ='<?php echo $eventViewURL . h($uuid);?>'">
				<?php echo nl2br(h($event['info'])); ?>&nbsp;
			</td>
			<td ondblclick="document.location.href ='<?php echo $eventViewURL . h($uuid);?>'" class="short"><?php echo h($event['timestamp']); ?></td>
			<td class="short action-links">
				<?php if ($feed['Feed']['enabled']) echo $this->Form->postLink('', '/feeds/getEvent/' . $id . '/' . $uuid, array('class' => 'icon-download', 'title' => 'Fetch the event'), __('Are you sure you want to fetch and save this event on your instance?', $this->Form->value('Feed.id'))); ?>
				<a href='<?php echo $eventViewURL . h($uuid);?>' class = "icon-list-alt" title = "View"></a>
			</td>
		</tr>
		<?php endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}'),
	'model' => 'Feed',
	));
	?>
	</p>
	<div class="pagination">
		<ul>
		<?php
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'previewIndex', 'id' => $id));
