<script>
function getTitle(incInt, incIntb, incIntc){
	id = incInt;
	type = null;
	if (incIntb==0){
		type = "R";
	}else{
		type = "A";
	}
	findElementString = type+id;
	if (type == "A"){
		findElementString += "X"+incIntc;
	}
	if (document.getElementById(findElementString).title == "Loading event info..."){
		$.ajax({
			type: 'GET',
			url: "/events/"+id+".xml",
			dataType: 'xml',
			async:false,
			success:function(result){
				var returnData = $(result).find("info").text();
				document.getElementById(findElementString).title=returnData;
			},
		});
	};
}
</script>
<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['org'] == $me['org']));
$mayPublish = ($isAclPublish && $event['Event']['org'] == $me['org']);
?>
<div class="events view">
<div class="actions" style="float:right;">
<?php if ( 0 == $event['Event']['published'] && ($isAdmin || $mayPublish)):
	// only show button if alert has not been sent  // LATER show the ALERT button in red-ish
	?>
	<ul><li><?php
	if ($isAdmin || $mayPublish) {
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
	<ul><li><?php echo $this->Html->link(__('Contact reporter', true), array('action' => 'contact', $event['Event']['id'])); ?> </li></ul>
</div>

<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?><?php echo $this->element('img', array('id' => $event['Event']['org']));?><?php
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
			<?php echo h($event['Event']['org']); ?>
			&nbsp;
		</dd>
		<?php
endif; ?>
		<?php if ('true' == Configure::read('CyDefSIG.showowner') || $isAdmin): ?>
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
		<?php
if ('true' == Configure::read('CyDefSIG.sync')): ?>
		<?php
	if ('true' == Configure::read('CyDefSIG.private')): ?>
		<dt>Distribution</dt>
		<dd>
			<?php echo $event['Event']['distribution'] . ', ' . strtolower(substr(($distributionDescriptions[$event['Event']['distribution']]['formdesc']), 0, 1)) . substr($distributionDescriptions[$event['Event']['distribution']]['formdesc'], 1) . '.'; ?>
			&nbsp;
		</dd>
		<?php
	else: ?>
		<dt>Private</dt>
		<dd>
			<?php echo ($event['Event']['private'])? 'Yes, never upload Event or any Attributes.' : 'No, upload Event and all Attributes except those marked as Private.'; ?>
			&nbsp;
		</dd>
		<?php
	endif; ?>
		<?php
endif; ?>
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
	</dl>
<?php
	$passAlong = array(0, 0);
if (!empty($relatedEvents)):?>
	<div class="related">
		<h3>Related Events</h3>
		<ul>
		<?php
	foreach ($relatedEvents as $relatedEvent): ?>
		<li><?php
		$linkText = $relatedEvent['Event']['date'] . ' (' . $relatedEvent['Event']['id'] . ')';
		$currentID = $relatedEvent['Event']['id'];
		$passAlong[0] = $relatedEvent['Event']['id'];
		echo "<div id = \"R" . $currentID . "\" onMouseOver=getTitle(" . $passAlong[0] . "," . $passAlong[1] . ") title = \"Loading event info...\">";
		echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id']));
		?></li>
		<?php
	endforeach; ?>
		</ul>
	</div>
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
			<?php
	if ('true' == Configure::read('CyDefSIG.sync')): ?>
			<?php
		if ('true' == Configure::read('CyDefSIG.private')): ?>
			<th <?php echo "title='" . $attrDescriptions['private']['desc'] . "'";?>>Distribution</th>
			<?php
		else:?>
			<th <?php echo "title='" . $attrDescriptions['private']['desc'] . "'";?>>Private</th>
			<?php
		endif;?>
			<?php
	endif;?>
			<?php
	if ($isAdmin || $mayModify): ?>
			<th class="actions">Actions</th>
			<?php
	endif;?>
		</tr><?php
	$passAlong = array(0, 1, 0);
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
				$filenameHash = explode('|', h($attribute['value']));
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
				$filenameHash = explode('|', h($attribute['value']));
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
					$passAlong[0] = $relatedAttribute['Attribute']['event_id'];
					echo "<span id = \"A" . $passAlong[0] . "X" . $passAlong[2] . "\" onMouseOver=getTitle(" . $passAlong[0] . "," . $passAlong[1] . "," . $passAlong[2] . ") title = \"Loading event info...\">";
					echo $this->Html->link($relatedAttribute['Attribute']['event_id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['Attribute']['event_id']));
					echo "</span>";
					echo ' ';
					$passAlong[2]++;
				}
			}
				?>&nbsp;
				</td>
				<td class="short" style="text-align: center;"><?php echo $attribute['to_ids'] ? 'Yes' : 'No';?></td>
				<?php
			if ('true' == Configure::read('CyDefSIG.sync')): ?>
				<?php
				if ('true' == Configure::read('CyDefSIG.private')): ?>
					<td class="short" style="text-align: center;"><?php echo $attribute['distribution'] != 'All communities' ? $attribute['distribution'] : 'All';?></td>
					<?php
				else:?>
					<td class="short" style="text-align: center;"><?php echo $attribute['private'] ? 'Private' : '&nbsp;';?></td>
					<?php
				endif;?>
				<?php
			endif;?>
				<?php
			if ($isAdmin || $mayModify): ?>
				<td class="actions">
					<?php
					echo $this->Html->link(__('Edit', true), array('controller' => 'attributes', 'action' => 'edit', $attribute['id']));
					echo $this->Form->postLink(__('Delete'), array('controller' => 'attributes', 'action' => 'delete', $attribute['id']), null, __('Are you sure you want to delete this attribute?'));
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
		<?php
if ($isAdmin || $mayModify): ?>
		<div class="actions">
			<ul>
				<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']));?> </li>
				<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']));?> </li>
			</ul>
		</div>
		<?php
endif; ?>
	</div>

</div>
<div class="actions">
	<ul>
	<?php
if ($isAdmin || $mayModify): ?>
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
