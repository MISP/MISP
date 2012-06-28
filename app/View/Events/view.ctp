<?php
$button_add_status = $isAclAdd || $event['Event']['user_id'] == $me['id'] ? 'button_on':'button_off';
$may_modify = $isAclModify || $event['Event']['user_id'] == $me['id']; $button_modify_status = $may_modify ? 'button_on':'button_off';
$may_publish = $isAclPublish || $event['Event']['user_id'] == $me['id']; $button_publish_status = $may_publish ? 'button_on':'button_off';
$buttonCounter = 0;
?>
<div class="events view">
<div class="actions" style="float:right;">
<?php if ( 0 == $event['Event']['published'] && ($isAdmin || $event['Event']['org'] == $me['org'])):
// only show button if alert has not been sent  // LATER show the ALERT button in red-ish
?>
    <ul><li><?php
    if ($may_publish) {
    	echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?');
    	echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $event['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!');
    } else {
    	echo $this->Html->link('Publish Event', array('action' => 'alert', $event['Event']['id']), array('id' => $button_publish_status.$buttonCounter++, 'class' => $button_publish_status));
    	echo $this->Html->link('Publish (no email)', array('action' => 'publish', $event['Event']['id']), array('id' => $button_publish_status.$buttonCounter++, 'class' => $button_publish_status));
    }
    ?> </li></ul>
<?php elseif (0 == $event['Event']['published']): ?>
    <ul><li>Not published</li></ul>
<?php else: ?>
    <!-- ul><li>Alert already sent</li></ul -->
<?php endif; ?>
    <ul><li><?php echo $this->Html->link(__('Contact reporter', true), array('action' => 'contact', $event['Event']['id'])); ?> </li></ul>
</div>



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
		<dt>Date</dt>
		<dd>
			<?php echo h($event['Event']['date']); ?>
			&nbsp;
		</dd>
		<dt<?php echo ' title="' . $event_descriptions['risk']['desc'] . '"';?>>Risk</dt>
		<dd>
			<?php echo $event['Event']['risk']; ?>
			&nbsp;
		</dd>
		<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
		<dt>Private</dt>
		<dd>
			<?php echo ($event['Event']['private'])? 'Yes, never upload Event or any Attributes.' : 'No, upload Event and all Attributes except those marked as Private.'; ?>
			&nbsp;
		</dd>
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
		$link_text = $relatedEvent['Event']['date'].' ('.$relatedEvent['Event']['id'].')';
		echo $this->Html->link($link_text, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id']));
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
    		<th <?php echo "title='" . $attr_descriptions['signature']['desc'] . "'";?>>IDS Signature</th>
    		<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
    		<th <?php echo "title='" . $attr_descriptions['private']['desc'] . "'";?>>Private</th>
    		<?php endif;?>
    		<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
    		<th class="actions">Actions</th>
    		<?php endif;?>
    	</tr>
    	<?php
        foreach ($categories as $category):
			$first = 1;
    		foreach ($event['Attribute'] as $attribute):
    			if($attribute['category'] != $category) continue;
    		?>
    		<tr>
    		    <td class="short" title="<?php if('' != $attribute['category']) echo $category_definitions[$attribute['category']]['desc'];?>"><?php
    		    if ($first) {
    		        if ('' == $attribute['category']) echo '(no category)';
    		        echo $attribute['category'];
    		    } else {
    		        echo '&nbsp;';
    		    }
    		    ?></td>
    			<td class="short" title="<?php echo $type_definitions[$attribute['type']]['desc'];?>"><?php echo $attribute['type'];?></td>
    			<td><?php
    			$sig_display = nl2br(h($attribute['value']));
    			if('attachment' == $attribute['type'] ||
    			        'malware-sample' == $attribute['type'] ) {
			        $filename_hash = explode('|', h($attribute['value']));
			        echo $this->Html->link($filename_hash[0], array('controller' => 'attributes', 'action' => 'download', $attribute['id']));
			        if (isset($filename_hash[1])) echo ' | '.$filename_hash[1];
    			} elseif (strpos($attribute['type'], '|') !== false) {
    			    $filename_hash = explode('|', h($attribute['value']));
    			    echo $filename_hash[0];
    			    if (isset($filename_hash[1])) echo ' | '.$filename_hash[1];
    			} elseif ('vulnerability' == $attribute['type']) {
    			    echo $this->Html->link($sig_display, 'http://www.google.com/search?q='.$sig_display, array('target'=> '_blank'));
    			} else {
    			    echo $sig_display;
    			}
    		    ?></td>
    			<td class="short" style="text-align: center;">
    			<?php
    			$first = 0;
                if (null != $relatedAttributes[$attribute['id']]) {
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
    				    	echo $this->Html->link(__('Edit', true), array('controller' => 'attributes', 'action' => 'edit', $attribute['id']), array('id' =>$button_modify_status.$buttonCounter++,'class' => $button_modify_status));
    				    	echo $this->Html->link(__('Delete'), array('controller' => 'attributes', 'action' => 'delete', $attribute['id']), array('id' =>$button_modify_status.$buttonCounter++,'class' => $button_modify_status));
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
    			<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']), array('id' =>$button_add_status.$buttonCounter++,'class' => $button_add_status));?> </li>
    			<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']),array('id' =>$button_add_status.$buttonCounter++,'class' => $button_add_status));?> </li>
    		</ul>
    	</div>
    	<?php endif; ?>
    </div>

</div>

<div class="actions">
	<ul>
	<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
    	<li><?php echo $this->Html->link(__('Add Attribute', true), array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']), array('id' =>$button_add_status.$buttonCounter++,'class' => $button_add_status));?> </li>
		<li><?php echo $this->Html->link(__('Add Attachment', true), array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']), array('id' =>$button_add_status.$buttonCounter++,'class' => $button_add_status));?> </li>
		<li><?php echo $this->Html->link(__('Edit Event', true), array('action' => 'edit', $event['Event']['id']),	array('id' =>$button_modify_status.$buttonCounter++,'class' => $button_modify_status)); ?> </li>
		<li><?php
			if ($may_modify) echo $this->Form->postLink(__('Delete Event'), array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id']));
			else echo $this->Html->link(__('Delete Event'), array('action' => 'delete', $event['Event']['id']), array('id' =>$button_modify_status.$buttonCounter++,'class' => $button_modify_status));
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