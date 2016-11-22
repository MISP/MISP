<table class="table table-striped table-hover table-condensed">
	<tr>
		<th class="filter">
			<?php echo $this->Paginator->sort('published');?>
		</th>
		<?php
			if (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg')):
		?>
			<th class="filter"><?php echo $this->Paginator->sort('Org', 'Source org'); ?></th>
			<th class="filter"><?php echo $this->Paginator->sort('Org', 'Member org'); ?></th>
		<?php
			else:
				if (Configure::read('MISP.showorg') || $isAdmin):
		?>
					<th class="filter"><?php echo $this->Paginator->sort('Org'); ?></th>
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
		<th title="Attribute Count"><?php echo $this->Paginator->sort('attribute_count', '#Attr.');?></th>
		<?php if (Configure::read('MISP.showCorrelationsOnIndex')):?>
			<th title="Correlation Count">#Corr.</th>
		<?php endif; ?>
		<?php if (Configure::read('MISP.showSightingsCountOnIndex') && Configure::read('Plugin.Sightings_enable') !== false):?>
			<th title="Sigthing Count">#Sightings</th>
		<?php endif; ?>
		<?php if (Configure::read('MISP.showProposalsOnIndex')):?>
			<th title="Proposal Count">#Prop</th>
		<?php endif; ?>
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
	<tr <?php if ($event['Event']['distribution'] == 0) echo 'class = "privateRed"'?>>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
			<?php
			if ($event['Event']['published'] == 1) {
			?>
				<a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>" class = "icon-ok" title = "View"></a>
			<?php
			} else {
			?>
				<a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>" class = "icon-remove" title = "View"></a>
			<?php
			}?>&nbsp;
		</td>
		<?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
			<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/organisations/view/".$event['Orgc']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($event['Orgc']['name']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Orgc']['name']) . '.png', array('alt' => h($event['Orgc']['name']), 'title' => h($event['Orgc']['name']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($event['Orgc']['name']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				&nbsp;
			</td>
		<?php endif;?>
		<?php if ($isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))): ?>
			<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/organisations/view/".$event['Org']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($event['Org']['name']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Org']['name']) . '.png', array('alt' => h($event['Org']['name']), 'title' => h($event['Org']['name']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($event['Org']['name']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				&nbsp;
			</td>
		<?php endif; ?>
		<td style="width:30px;">
			<a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>"><?php echo $event['Event']['id'];?></a>
		</td>
		<?php if (Configure::read('MISP.tagging')): ?>
			<td style = "max-width: 200px;width:10px;">
				<?php foreach ($event['EventTag'] as $tag):
					$tagText = "&nbsp;";
					if (Configure::read('MISP.full_tags_on_event_index') == 1) $tagText = h($tag['Tag']['name']);
					else if (Configure::read('MISP.full_tags_on_event_index') == 2) {
						if (strpos($tag['Tag']['name'], '=')) {
							$tagText = explode('=', $tag['Tag']['name']);
							$tagText = h(trim(end($tagText), "\""));
						}
						else $tagText = h($tag['Tag']['name']);
					}
				?>
					<span class="tag useCursorPointer" style="margin-bottom:3px;background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>;" title="<?php echo h($tag['Tag']['name']); ?>" onClick="document.location.href='<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($tag['Tag']['id']);?>';"><?php echo $tagText; ?></span>
				<?php endforeach; ?>
			</td>
		<?php endif; ?>
		<td style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
			<?php echo $event['Event']['attribute_count']; ?>&nbsp;
		</td>
		<?php if (Configure::read('MISP.showCorrelationsOnIndex')):?>
			<td class = "bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['correlation_count']) ? h($event['Event']['correlation_count']) : '0') . ' correlation(s)';?>">
				<?php echo !empty($event['Event']['correlation_count']) ? h($event['Event']['correlation_count']) : ''; ?>&nbsp;
			</td>
		<?php endif; ?>
		<?php if (Configure::read('MISP.showSightingsCountOnIndex') && Configure::read('Plugin.Sightings_enable') !== false):?>
			<td class = "bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['sightings_count']) ? h($event['Event']['sightings_count']) : '0') . ' sighting(s)';?>">
				<?php echo !empty($event['Event']['sightings_count']) ? h($event['Event']['sightings_count']) : ''; ?>&nbsp;
			</td>
		<?php endif; ?>
		<?php if (Configure::read('MISP.showProposalsOnIndex')): ?>
			<td class = "bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : '0') . ' proposal(s)';?>">
				<?php echo !empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : ''; ?>&nbsp;
			</td>
		<?php endif;?>
		<?php if ('true' == $isSiteAdmin): ?>
			<td class="short" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
				<?php echo h($event['User']['email']); ?>&nbsp;
			</td>
		<?php endif; ?>
		<td class="short" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
			<?php echo $event['Event']['date']; ?>&nbsp;
		</td>
		<td class="short" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
			<?php
			if ($event['ThreatLevel']['name']) echo h($event['ThreatLevel']['name']);
			else echo h($event['Event']['threat_level_id']);
			?>&nbsp;
		</td>
		<td class="short" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
			<?php echo $analysisLevels[$event['Event']['analysis']]; ?>&nbsp;
		</td>
		<td ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
			<?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;
		</td>
		<td class="short <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" ondblclick="location.href ='<?php echo $baseurl; ?>/events/view/<?php echo $event['Event']['id'];?>'" title = "<?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : 'All';?>">
			<?php if ($event['Event']['distribution'] == 4):?>
				<a href="<?php echo $baseurl;?>/sharingGroups/view/<?php echo h($event['SharingGroup']['id']); ?>"><?php echo h($event['SharingGroup']['name']);?></a>
			<?php else:
				echo h($shortDist[$event['Event']['distribution']]);
			endif;
			?>
		</td>
		<td class="short action-links">
			<?php
				if (0 == $event['Event']['published'] && ($isSiteAdmin || ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id'])))
					echo $this->Form->postLink('', array('action' => 'alert', $event['Event']['id']), array('class' => 'icon-download-alt', 'title' => 'Publish Event'), 'Are you sure this event is complete and everyone should be informed?');
				else if (0 == $event['Event']['published']) echo 'Not published';
	
				if ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id'])):
			?>
					<a href='<?php echo $baseurl."/events/edit/".$event['Event']['id'];?>' class = "icon-edit" title = "Edit"></a>
			<?php
					echo $this->Form->postLink('', array('action' => 'delete', $event['Event']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete # %s?', $event['Event']['id']));
				endif;
			?>
			<a href='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>' class = "icon-list-alt" title = "View"></a>
		</td>
	</tr>
	<?php endforeach; ?>
</table>