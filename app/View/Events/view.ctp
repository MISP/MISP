<div class="events view">
<div class="actions" style="float:right;">
<?php if ( 0 == $event['Event']['alerted'] && ($isAdmin || $event['Event']['org'] == $me['org'])): 
// only show button if alert has not been sent  // LATER show the ALERT button in red-ish 
?>
    <ul><li><?php 
    echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be alerted?');
    ?> </li></ul>
<?php elseif (0 == $event['Event']['alerted']): ?>
    <ul><li>Not finished editing</li></ul>
<?php else: ?>
    <!-- ul><li>Alert already sent</li></ul -->
<?php endif; ?>
    <ul><li><?php echo $this->Html->link(__('Contact reporter', true), array('action' => 'contact', $event['Event']['id'])); ?> </li></ul>
</div>



<h2>Event</h2>
	<dl>
		<dt>ID</dt>
		<dd>
			<?php echo Sanitize::html($event['Event']['id']); ?>
			&nbsp;
		</dd>
		<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
		<dt>Org</dt>
		<dd>
			<?php echo Sanitize::html($event['Event']['org']); ?>
			&nbsp;
		</dd>
		<?php endif; ?>
		<dt>Date</dt>
		<dd>
			<?php echo Sanitize::html($event['Event']['date']); ?>
			&nbsp;
		</dd>
		<dt>Risk</dt>
		<dd>
			<?php echo $event['Event']['risk']; ?>
			&nbsp;
		</dd>
		<!-- dt>UUID</dt>
		<dd>
			<?php echo $event['Event']['uuid']; ?>
			&nbsp;
		</dd -->
		<dt>Info</dt>
		<dd>
			<?php echo nl2br(Sanitize::html($event['Event']['info'])); ?>
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
	</div>
	<?php endif; ?>
	
    <div class="related">
    	<h3>Signatures</h3>
    	<?php if (!empty($event['Signature'])):?>
    	<table cellpadding = "0" cellspacing = "0">
    	<tr>
    		<th>Type</th>
    		<th>Value</th>
    		<th>Related Events</th>
    		<th>To IDS</th>
    		<th class="actions" style="text-align:right;">Actions</th>
    	</tr>
    	<?php
    		foreach ($event['Signature'] as $signature):
    		?>
    		<tr>
    			<td><?php echo $signature['type'];?></td>
    			<td><?php echo nl2br(Sanitize::html($signature['value']));?></td>
    			<td>
    			<?php
    			if (null != $relatedSignatures[$signature['id']]) {
    			    foreach ($relatedSignatures[$signature['id']] as $relatedSignature) {
    			        echo $this->Html->link($relatedSignature['Signature']['event_id'], array('controller' => 'events', 'action' => 'view', $relatedSignature['Signature']['event_id']));
    			        echo ' '; 
    			    }
    			}
    			?>
    			</td>
    			<td><?php echo $signature['to_ids'] ? 'Yes' : 'No';?></td>
    			<td class="actions" style="text-align:right;">
    				<?php
    				if ($isAdmin || $event['Event']['org'] == $me['org']) { 
    				    echo $this->Html->link(__('Edit', true), array('controller' => 'signatures', 'action' => 'edit', $signature['id'])); 
    				    echo $this->Form->postLink(__('Delete'), array('controller' => 'signatures', 'action' => 'delete', $signature['id']), null, __('Are you sure you want to delete this signature?')); 
    				} ?>
    			</td>
    		</tr>
    	    <?php endforeach; ?>
    	</table>
        <?php endif; ?>
    	<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
    	<div class="actions">
    		<ul>
    			<li><?php echo $this->Html->link('New Signature', array('controller' => 'signatures', 'action' => 'add', $event['Event']['id']));?> </li>
    		</ul>
    	</div>
    	<?php endif; ?>
    </div>

</div>

<div class="actions">
	<ul>
	<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
    	<li><?php echo $this->Html->link(__('New Signature', true), array('controller' => 'signatures', 'action' => 'add', $event['Event']['id']));?> </li>
		<li><?php echo $this->Html->link(__('Edit Event', true), array('action' => 'edit', $event['Event']['id'])); ?> </li>
		<li><?php echo $this->Form->postLink(__('Delete Event'), array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id'])); ?></li>
		<li>&nbsp;</li>
	<?php endif; ?>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

