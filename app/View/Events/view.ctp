<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['org'] == $me['org']));
$mayPublish = ($isAclPublish && $event['Event']['org'] == $me['org']);
?>
<div class="events view">
<div class="actions" style="float:right;">
	<?php
		if ($isSiteAdmin || $mayModify): ?>
	<ul><li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']));?>
	<?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']));?> </li></ul><br />
		<?php
endif; ?>
<?php if ( 0 == $event['Event']['published'] && ($isAdmin || $mayPublish)):
	// only show button if alert has not been sent  // LATER show the ALERT button in red-ish
	?>
	<ul><li><?php
	if ($isSiteAdmin || $mayPublish) {
		echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?');
		echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $event['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!');
	}
	?> </li></ul>
	<?php elseif (0 == $event['Event']['published']): ?>
		<ul><li>Not published</li></ul>
	<?php else: ?>
		<!-- ul><li>Alert already sent</li></ul -->
	<?php
endif; ?>
	<br /><ul><li><?php echo $this->Html->link(__('Contact reporter', true), array('action' => 'contact', $event['Event']['id'])); ?> </li></ul><br />
	<ul><li><?php echo $this->Html->link(__('Download as XML', true), array('action' => 'downloadxml', $event['Event']['id'])); ?>
	<?php echo $this->Html->link(__('Download as IOC', true), array('action' => 'downloadOpenIOCEvent', $event['Event']['id'])); ?> </li></ul>
</div>

<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?><?php echo $this->element('img', array('id' => $event['Event']['orgc']));?><?php
endif; ?>
<h2>Event</h2>
	<dl>
		<dt>ID</dt>
		<dd>
			<?php echo h($event['Event']['id']); ?>
			&nbsp;
		</dd>
		<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
		<dt>Org</dt>
		<dd>
			<?php echo h($event['Event']['orgc']); ?>
			&nbsp;
		</dd>
		<?php
endif; ?>
		<?php if ($isSiteAdmin): ?>
		<dt>Owner org</dt>
		<dd>
			<?php echo h($event['Event']['org']); ?>
			&nbsp;
		</dd>
		<?php
endif; ?>
		<?php if ($isSiteAdmin || ($isAdmin && $me['org'] == $event['Event']['org'])): ?>
		<dt>Email</dt>
		<dd>
			<?php echo h($event['User']['email']); ?>
			&nbsp;
		</dd>
		<?php
endif; ?>
		<dt>Date</dt>
		<dd>
			<?php echo h($event['Event']['date']); ?>
			&nbsp;
		</dd>
		<dt<?php echo ' title="' . $eventDescriptions['risk']['desc'] . '"';?>>Risk</dt>
		<dd>
			<?php echo $event['Event']['risk']; ?>
			&nbsp;
		</dd>
		<dt<?php echo ' title="' . $eventDescriptions['analysis']['desc'] . '"';?>>Analysis</dt>
		<dd>
			<?php echo $analysisLevels[$event['Event']['analysis']]; ?>
			&nbsp;
		</dd>

	<dt>Distribution</dt>
	<dd>
		<?php echo $event['Event']['distribution'] . ', ' . strtolower(substr(($distributionDescriptions[$event['Event']['distribution']]['formdesc']), 0, 1)) . substr($distributionDescriptions[$event['Event']['distribution']]['formdesc'], 1) . '.'; ?>
		&nbsp;
	</dd>
		<!-- dt>UUID</dt>
		<dd>
			<?php echo $event['Event']['uuid']; ?>
			&nbsp;
		</dd -->
		<dt>Info</dt>
		<dd>
			<?php echo nl2br(h($event['Event']['info'])); ?>
			&nbsp;
		</dd>
	</dl><br />
<?php
if (!empty($relatedEvents)):?>
	<div class="related">
		<h3>Related Events</h3>
		<ul>
		<?php
	foreach ($relatedEvents as $relatedEvent): ?>
		<li><?php
		$linkText = $relatedEvent['Event']['date'] . ' (' . $relatedEvent['Event']['id'] . ')';
		echo "<div \" title = \"".h($relatedEvent['Event']['info'])."\">";
		if ($relatedEvent['Event']['org'] == $me['org']) {
			echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id']), array('class' => 'SameOrgLink'));
		} else {
			echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id']));
		}
		?></li>
		<?php
	endforeach; ?>
		</ul>
	</div><br />
	<?php
endif; ?>

	<div class="related">
		<h3>Attributes</h3>
		<?php
if (!empty($event['Attribute'])):?>
		<table cellpadding = "0" cellspacing = "0">
		<tr>
			<th>Category</th>
			<th>Type</th>
			<th>Value</th>
			<th>Related Events</th>
			<th <?php echo "title='" . $attrDescriptions['signature']['desc'] . "'";?>>IDS Signature</th>
			<th <?php echo "title='" . $attrDescriptions['private']['desc'] . "'";?>>Distribution</th>
			<?php
	if ($isAdmin || $mayModify): ?>
			<th class="actions">Actions</th>
			<?php
	endif;?>
		</tr><?php
	foreach ($categories as $category):
		$first = 1;
		foreach ($event['Attribute'] as $attribute):
			if ($attribute['category'] != $category) continue;?>
			<tr>
				<td class="short" title="<?php if('' != $attribute['category']) echo $categoryDefinitions[$attribute['category']]['desc'];?>"><?php
			if ($first) {
				if ('' == $attribute['category']) echo '(no category)';
					echo $attribute['category'];
			} else {
				echo '&nbsp;';
			}?></td>
			<td class="short" title="<?php
			echo $typeDefinitions[$attribute['type']]['desc'];?>"><?php
			echo $attribute['type'];?></td>
				<td><?php
			$sigDisplay = nl2br(h($attribute['value']));
			if ('attachment' == $attribute['type'] || 'malware-sample' == $attribute['type'] ) {
				$filenameHash = explode('|', nl2br(h($attribute['value'])));
				if (strrpos($filenameHash[0], '\\')) {
					$filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
					$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
					echo $filepath;
					echo $this->Html->link($filename, array('controller' => 'attributes', 'action' => 'download', $attribute['id']));
				} else {
					echo $this->Html->link($filenameHash[0], array('controller' => 'attributes', 'action' => 'download', $attribute['id']));
				}
				if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
			} elseif (strpos($attribute['type'], '|') !== false) {
				$filenameHash = explode('|', $attribute['value']);
				echo $filenameHash[0];
				if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
			} elseif ('vulnerability' == $attribute['type']) {
				echo $this->Html->link($sigDisplay, 'http://www.google.com/search?q=' . $sigDisplay, array('target' => '_blank'));
			} elseif ('link' == $attribute['type']) {
				echo $this->Html->link($sigDisplay, $sigDisplay);
			} else {
				echo $sigDisplay;
			}
				?></td>
				<td class="short" style="text-align: center;">
				<?php
			$first = 0;
			if (isset($relatedAttributes[$attribute['id']]) && (null != $relatedAttributes[$attribute['id']])) {
				foreach ($relatedAttributes[$attribute['id']] as $relatedAttribute) {
					echo "<span title = \"".h($relatedAttribute['Attribute']['event_info'])."\">";
					if ($relatedAttribute['Attribute']['relatedOrg'] == $me['org']) {
						echo $this->Html->link($relatedAttribute['Attribute']['event_id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['Attribute']['event_id']), array ('class' => 'SameOrgLink'));
					} else {
						echo $this->Html->link($relatedAttribute['Attribute']['event_id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['Attribute']['event_id']));
					}

					echo "</span>";
					echo ' ';
				}
			}
				?>&nbsp;
				</td>
				<td class="short" style="text-align: center;"><?php echo $attribute['to_ids'] ? 'Yes' : 'No';?></td>
				<td class="short" style="text-align: center;"><?php echo $attribute['distribution'] != 'All communities' ? $attribute['distribution'] : 'All';?></td>
				<?php
			if ($isSiteAdmin || $mayModify): ?>
				<td class="actions">
					<?php
					echo $this->Html->link(__('Edit', true), array('controller' => 'attributes', 'action' => 'edit', $attribute['id']));
					echo $this->Form->postLink(__('Delete'), array('controller' => 'attributes', 'action' => 'delete', $attribute['id']), null, __('Are you sure you want to delete this attribute? Keep in mind that this will also delete this attribute on remote MISP instances.'));
					?>
				</td>
				<?php
			endif;?>
			</tr>
			<?php
		endforeach; ?>
		<?php
	endforeach; ?>
		</table>
		<?php
endif; ?>
	</div>

</div>
<div class="actions">
	<ul>
	<?php
if ($isSiteAdmin || $mayModify): ?>
		<li><?php echo $this->Html->link(__('Add Attribute', true), array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']));?> </li>
		<li><?php echo $this->Html->link(__('Add Attachment', true), array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']));?> </li>
		<li><?php echo $this->Html->link(__('Edit Event', true), array('action' => 'edit', $event['Event']['id'])); ?> </li>
		<li><?php echo $this->Form->postLink(__('Delete Event'), array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id'])); ?></li>
		<li>&nbsp;</li>
	<?php
endif; ?>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
