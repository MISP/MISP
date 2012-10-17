<?php
$buttonAddStatus = $isAclAdd || $event['Event']['user_id'] == $me['id'] ? 'button_on':'button_off';
$mayModify = $isAclModify || $event['Event']['user_id'] == $me['id'];
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
$mayPublish = $isAclPublish || $event['Event']['user_id'] == $me['id'];
$buttonPublishStatus = $mayPublish ? 'button_on':'button_off';
$buttonCounter = 0;
?>
<div class="events view">
<div class="actions" style="float:right;">
<?php if ( 0 == $event['Event']['published'] && ($isAdmin || $event['Event']['org'] == $me['org'])):
// only show button if alert has not been sent  // LATER show the ALERT button in red-ish
?>
	<ul><li><?php
if ($mayPublish) {
	echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?');
	echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $event['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!');
} else {
	echo $this->Html->link('Publish Event', array('action' => 'alert', $event['Event']['id']), array('id' => $buttonPublishStatus . $buttonCounter++, 'class' => $buttonPublishStatus));
	echo $this->Html->link('Publish (no email)', array('action' => 'publish', $event['Event']['id']), array('id' => $buttonPublishStatus . $buttonCounter++, 'class' => $buttonPublishStatus));
}
	?> </li></ul>
<?php elseif (0 == $event['Event']['published']): ?>
	<ul><li>Not published</li></ul>
<?php else: ?>
	<!-- ul><li>Alert already sent</li></ul -->
<?php endif; ?>
	<ul><li><?php echo $this->Html->link(__('Contact reporter', true), array('action' => 'contact', $event['Event']['id'])); ?> </li></ul>
</div>

<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
<?php echo $this->Html->image('orgs/' . h($event['Event']['org']) . '.png', array('alt' => h($event['Event']['org']),'width' => '50','hight' => '50', 'style' => 'float:right;')); ?>
<?php endif; ?>
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
		<?php endif; ?>
		<?php if ('true' == Configure::read('CyDefSIG.showowner') || $isAdmin): ?>
		<dt>Email</dt>
		<dd>
			<?php echo h($event['User']['email']); ?>
			&nbsp;
		</dd>
		<?php endif; ?>
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
		<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
		<?php if ('true' == Configure::read('CyDefSIG.private')): ?>
		<dt>Private</dt>
		<dd>
			<?php echo ($event['Event']['sharing'] == 'All') ? 'upload Event and all Attributes except those marked as to keep in Org or Server.' : (($event['Event']['sharing'] == 'Server') ? 'Server, Only show Event or any Attributes to Server members.': 'Org, Only show Event or any Attributes to Org members.'); ?>
			&nbsp;
		</dd>
		<?php else: ?>
		<dt>Private</dt>
		<dd>
			<?php echo ($event['Event']['private'])? 'Yes, never upload Event or any Attributes.' : 'No, upload Event and all Attributes except those marked as Private.'; ?>
			&nbsp;
		</dd>
		<?php endif; ?>
		<?php endif; ?>
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
	<?php if (!empty($relatedEvents)):?>
	<div class="related">
		<h3>Related Events</h3>
		<ul>
		<?php foreach ($relatedEvents as $relatedEvent): ?>
		<li><?php
		$linkText = $relatedEvent['Event']['date'] . ' (' . $relatedEvent['Event']['id'] . ')';
		echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id']));
		?></li>
		<?php endforeach; ?>
		</ul>
	</div>
	<?php endif; ?>

	<div class="related">
		<h3>Attributes</h3>
		<?php if (!empty($event['Attribute'])):?>
		<table cellpadding = "0" cellspacing = "0">
		<tr>
			<th>Category</th>
			<th>Type</th>
			<th>Value</th>
			<th>Related Events</th>
			<th <?php echo "title='" . $attrDescriptions['signature']['desc'] . "'";?>>IDS Signature</th>
			<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
			<th <?php echo "title='" . $attrDescriptions['private']['desc'] . "'";?>>Private</th>
			<?php endif;?>
			<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
			<th class="actions">Actions</th>
			<?php endif;?>
		</tr><?php
		foreach ($categories as $category):
			$first = 1;
			foreach ($event['Attribute'] as $attribute):
				if($attribute['category'] != $category) continue;
			?>
			<tr>
				<td class="short" title="<?php if('' != $attribute['category']) echo $categoryDefinitions[$attribute['category']]['desc'];?>"><?php
if ($first) {
	if ('' == $attribute['category']) echo '(no category)';
	echo $attribute['category'];
} else {
	echo '&nbsp;';
}
				?></td>
<td class="short" title="<?php echo $typeDefinitions[$attribute['type']]['desc'];?>"><?php echo $attribute['type'];?></td>
				<td><?php
$sigDisplay = nl2br(h($attribute['value']));
if ('attachment' == $attribute['type'] ||
		'malware-sample' == $attribute['type'] ) {
	$filenameHash = explode('|', h($attribute['value']));
	echo $this->Html->link($filenameHash[0], array('controller' => 'attributes', 'action' => 'download', $attribute['id']));
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
		echo $this->Html->link($relatedAttribute['Attribute']['event_id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['Attribute']['event_id']));
		echo ' ';
	}
}
				?>&nbsp;
				</td>
				<td class="short" style="text-align: center;"><?php echo $attribute['to_ids'] ? 'Yes' : 'No';?></td>
				<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
				<td class="short" style="text-align: center;"><?php echo $attribute['private'] ? 'Private' : '&nbsp;';?></td>
				<?php endif;?>
				<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
				<td class="actions">
					<?php
if ($isAclModify) {
	echo $this->Html->link(__('Edit', true), array('controller' => 'attributes', 'action' => 'edit', $attribute['id']));
	echo $this->Form->postLink(__('Delete'), array('controller' => 'attributes', 'action' => 'delete', $attribute['id']), null, __('Are you sure you want to delete this attribute?'));
} else {
	echo $this->Html->link(__('Edit', true), array('controller' => 'attributes', 'action' => 'edit', $attribute['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus));
	echo $this->Html->link(__('Delete'), array('controller' => 'attributes', 'action' => 'delete', $attribute['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus));
}
					?>
				</td>
				<?php endif;?>
			</tr>
			<?php endforeach; ?>
		<?php endforeach; ?>
		</table>
		<?php endif; ?>
		<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
		<div class="actions">
			<ul>
				<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']), array('id' => $buttonAddStatus . $buttonCounter++, 'class' => $buttonAddStatus));?> </li>
				<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']), array('id' => $buttonAddStatus . $buttonCounter++, 'class' => $buttonAddStatus));?> </li>
			</ul>
		</div>
		<?php endif; ?>
	</div>

</div>

<div class="actions">
	<ul>
	<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
		<li><?php echo $this->Html->link(__('Add Attribute', true), array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']), array('id' => $buttonAddStatus . $buttonCounter++, 'class' => $buttonAddStatus));?> </li>
		<li><?php echo $this->Html->link(__('Add Attachment', true), array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']), array('id' => $buttonAddStatus . $buttonCounter++,'class' => $buttonAddStatus));?> </li>
		<li><?php echo $this->Html->link(__('Edit Event', true), array('action' => 'edit', $event['Event']['id']),	array('id' => $buttonModifyStatus . $buttonCounter++,'class' => $buttonModifyStatus)); ?> </li>
		<li><?php
			if ($mayModify) echo $this->Form->postLink(__('Delete Event'), array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id']));
			else echo $this->Html->link(__('Delete Event'), array('action' => 'delete', $event['Event']['id']), array('id' => $buttonModifyStatus . $buttonCounter++,'class' => $buttonModifyStatus));
		?></li>
		<li>&nbsp;</li>
	<?php endif; ?>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

<!--?php $javascript->link('deactivateButtons.js', false); ?-->
<!--script type="text/javascript" src="deactivateButtons.js"></script-->
<script type="text/javascript">
$('#button_off').click(function() {
	return false;
});
$('#button_off0').click(function() {
	return false;
});
$('#button_off1').click(function() {
	return false;
});
$('#button_off2').click(function() {
	return false;
});
$('#button_off3').click(function() {
	return false;
});
$('#button_off4').click(function() {
	return false;
});
$('#button_off5').click(function() {
	return false;
});
$('#button_off6').click(function() {
	return false;
});
$('#button_off7').click(function() {
	return false;
});
$('#button_off8').click(function() {
	return false;
});
$('#button_off9').click(function() {
	return false;
});
$('#button_off10').click(function() {
	return false;
});
$('#button_off11').click(function() {
	return false;
});
$('#button_off12').click(function() {
	return false;
});
$('#button_off13').click(function() {
	return false;
});
$('#button_off14').click(function() {
	return false;
});
$('#button_off15').click(function() {
	return false;
});
$('#button_off16').click(function() {
	return false;
});
$('#button_off17').click(function() {
	return false;
});
$('#button_off10').click(function() {
	return false;
});
$('#button_off19').click(function() {
	return false;
});
$('#button_off20').click(function() {
	return false;
});
$('#button_off21').click(function() {
	return false;
});
$('#button_off22').click(function() {
	return false;
});
$('#button_off23').click(function() {
	return false;
});
$('#button_off24').click(function() {
	return false;
});
$('#button_off25').click(function() {
	return false;
});
$('#button_off26').click(function() {
	return false;
});
$('#button_off27').click(function() {
	return false;
});
$('#button_off28').click(function() {
	return false;
});
$('#button_off29').click(function() {
	return false;
});
$('#button_off30').click(function() {
	return false;
});
$('#button_off31').click(function() {
	return false;
});
$('#button_off32').click(function() {
	return false;
});
$('#button_off33').click(function() {
	return false;
});
$('#button_off34').click(function() {
	return false;
});
$('#button_off35').click(function() {
	return false;
});
$('#button_off36').click(function() {
	return false;
});
$('#button_off37').click(function() {
	return false;
});
$('#button_off38').click(function() {
	return false;
});
$('#button_off39').click(function() {
	return false;
});
</script>
