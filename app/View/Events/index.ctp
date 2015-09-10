<div class="events index">
	<h2>Events</h2>
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
	<?php
		$tab = "Center";
		$filtered = false;
		if (count($passedArgsArray) > 0) {
			$tab = "Left";
			$filtered = true;
		}
	?>
	<div class="tabMenuFixedContainer" style="display:inline-block;">
		<span class="tabMenuFixed tabMenuFixed<?php echo $tab; ?> tabMenuSides">
			<span id="create-button" title="Modify filters" class="icon-search useCursorPointer" onClick="getPopup('<?php echo h($urlparams);?>', 'events', 'filterEventIndex');"></span>
		</span>
		<?php if ($filtered):
			foreach ($passedArgsArray as $k => $v):?>
				<span class="tabMenuFixed tabMenuFixedElement">
					<?php echo h(ucfirst($k)) . " : " . h($v); ?>
				</span>
			<?php endforeach; ?>
		<span class="tabMenuFixed tabMenuFixedRight tabMenuSides">
			<?php echo $this->Html->link('', array('controller' => 'events', 'action' => 'index'), array('class' => 'icon-remove', 'title' => 'Remove filters'));?>
		</span>
		<?php endif;?>
		<span id="quickFilterButton" class="tabMenuFilterFieldButton useCursorPointer" onClick='quickFilterEvents(<?php echo h($passedArgs);?>);'>Filter</span>
		<input class="tabMenuFilterField" type="text" id="quickFilterField"></input>
	</div>
	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th class="filter">
				<?php echo $this->Paginator->sort('published');?>
			</th>
			<?php
				if (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg')):
			?>
				<th class="filter"><?php echo $this->Paginator->sort('org', 'Source org'); ?></th>
				<th class="filter"><?php echo $this->Paginator->sort('org', 'Member org'); ?></th>
			<?php 
				else:
					if (Configure::read('MISP.showorg') || $isAdmin): 
			?>
						<th class="filter"><?php echo $this->Paginator->sort('org'); ?></th>
			<?php
					endif;
					if ($isSiteAdmin):
			?>
				<th class="filter"><?php echo $this->Paginator->sort('owner org');?></th>
			<?php 
					endif;
				endif;
			?>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<?php if (Configure::read('MISP.tagging')): ?>
				<th class="filter">Tags</th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('attribute_count', '#Attr.');?></th>
			<?php if ($isSiteAdmin): ?>
			<th><?php echo $this->Paginator->sort('user_id', 'Email');?></th>
			<?php endif; ?>
			<th class="filter"><?php echo $this->Paginator->sort('date');?></th>
			<th class="filter" title="<?php echo $eventDescriptions['threat_level_id']['desc'];?>"><?php echo $this->Paginator->sort('threat_level_id');?></th>
			<th title="<?php echo $eventDescriptions['analysis']['desc'];?>">
				<?php echo $this->Paginator->sort('analysis');?>
			</th>
			<th class="filter"><?php echo $this->Paginator->sort('info');?></th>
			<th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
				<?php echo $this->Paginator->sort('distribution');?>
			</th>
			<th class="actions">Actions</th>

		</tr>
		<?php foreach ($events as $event): ?>
		<tr <?php if($event['Event']['distribution'] == 0) echo 'class = "privateRed"'?>>
			<td class="short" ondblclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php
				if ($event['Event']['published'] == 1) {
				?>
					<a href="/events/view/<?php echo $event['Event']['id'] ?>" class = "icon-ok" title = "View"></a>
				<?php
				} else {
				?>
					<a href="/events/view/<?php echo $event['Event']['id'] ?>" class = "icon-remove" title = "View"></a>
				<?php
				}?>&nbsp;
			</td>
			<?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
			<td class="short" ondblclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($event['Event']['orgc']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Event']['orgc']) . '.png', array('alt' => h($event['Event']['orgc']), 'title' => h($event['Event']['orgc']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($event['Event']['orgc']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				&nbsp;
			</td>
			<?php endif;?>
			<?php if ($isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))): ?>
			<td class="short" ondblclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($event['Event']['org']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Event']['org']) . '.png', array('alt' => h($event['Event']['org']), 'title' => h($event['Event']['org']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($event['Event']['org']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				&nbsp;
			</td>
			<?php endif; ?>
			<td style="width:30px;">
				<a href="/events/view/<?php echo $event['Event']['id'] ?>"><?php echo $event['Event']['id'];?></a>
			</td>
			<?php if (Configure::read('MISP.tagging')): ?>
			<td style = "max-width: 200px;width:10px;">
				<?php foreach ($event['EventTag'] as $tag):
					$tagText = "&nbsp;";
					if (Configure::read('MISP.full_tags_on_event_index')) $tagText = h($tag['Tag']['name']);
				?>
					<span class=tag style="margin-bottom:3px;background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>;" title="<?php echo h($tag['Tag']['name']); ?>"><?php echo $tagText; ?></span>
				<?php endforeach; ?>
			</td>
			<?php endif; ?>
			<td style="width:30px;" ondblclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo $event['Event']['attribute_count']; ?>&nbsp;
			</td>
			<?php if ('true' == $isSiteAdmin): ?>
			<td class="short" ondblclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo h($event['User']['email']); ?>&nbsp;
			</td>
			<?php endif; ?>
			<td class="short" ondblclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo $event['Event']['date']; ?>&nbsp;
			</td>
			<td class="short" ondblclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php 
				if ($event['ThreatLevel']['name']) echo h($event['ThreatLevel']['name']);
				else echo h($event['Event']['threat_level_id']);
				?>&nbsp;
			</td>
			<td class="short" ondblclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo $analysisLevels[$event['Event']['analysis']]; ?>&nbsp;
			</td>
			<td ondblclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;
			</td>
			<td class="short <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" ondblclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'" title = "<?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : 'All';?>">
				<?php echo $shortDist[$event['Event']['distribution']]; ?>
			</td>
			<td class="short action-links">
				<?php
				if (0 == $event['Event']['published'] && ($isSiteAdmin || ($isAclPublish && $event['Event']['org'] == $me['org'])))
					echo $this->Form->postLink('', array('action' => 'alert', $event['Event']['id']), array('class' => 'icon-download-alt', 'title' => 'Publish Event'), 'Are you sure this event is complete and everyone should be informed?');
				elseif (0 == $event['Event']['published']) echo 'Not published';

				if ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['org'] == $me['org'])) {
				?>
					<a href='/events/edit/<?php echo $event['Event']['id'];?>' class = "icon-edit" title = "Edit"></a>
				<?php
					echo $this->Form->postLink('', array('action' => 'delete', $event['Event']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete # %s?', $event['Event']['id']));
				}
				?>
				<a href='/events/view/<?php echo $event['Event']['id'];?>' class = "icon-list-alt" title = "View"></a>
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
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'index'));
?>
