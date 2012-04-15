<div class="events view">
<div class="actions" style="float:right;">
<?php if ( 0 == $event['Event']['published'] && ($isAdmin || $event['Event']['org'] == $me['org'])):
// only show button if alert has not been sent  // LATER show the ALERT button in red-ish
?>
    <ul><li><?php
    echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be published?');
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
	    </ul>
	    <br/>
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
    		<th>IDS Signature</th>
    		<th class="actions">Actions</th>
    	</tr>

    	<?php
	foreach ($categories as $category):
    		$i = 0;
		$first = 1;
    		foreach ($event['Attribute'] as $attribute):
	    		if($attribute['category'] != $category) continue;
			$class = null;
    			if ($i++ % 2 == 0) {
    				$class = ' class="altrow"';
    			}
    		?>
    		<tr<?php echo $class;?>>
    			<td><?php echo $first ? $category : '';?></td>
    			<td><?php echo $attribute['type'];?></td>
    			<td><?php 
			$sig_display = nl2br(Sanitize::html($attribute['value']));
			if('attachment' == $attribute['type'] ||
		  	 'malware-sample' == $attribute['type']) {
		 	   echo $this->Html->link($sig_display, array('controller' => 'attributes', 'action' => 'download', $attribute['id']));
			} elseif('link' == $attribute['type']) {
				?><A HREF="<?php echo $attribute['value']?>"><?php echo $attribute['value']?></A><?php	
			} else {
				echo $sig_display;
			}
            
                        ?>
                        </td>
    			<td>
    			<?php
    			$first = 0;
			if (null != $relatedAttributes[$attribute['id']]) {
    			    foreach ($relatedAttributes[$attribute['id']] as $relatedAttribute) {
    			        echo $this->Html->link($relatedAttribute['Attribute']['event_id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['Attribute']['event_id']));
    			        echo ' '; 
    			    }
    			}
    			?>
    			</td>
    			<td><?php echo $attribute['to_ids'] ? 'Yes' : 'No';?></td>
    			<td class="actions" style="text-align:right;">
    				<?php
    				if ($isAdmin || $event['Event']['org'] == $me['org']) { 
    				    echo $this->Html->link(__('Edit', true), array('controller' => 'attributes', 'action' => 'edit', $attribute['id'])); 
    				    echo $this->Form->postLink(__('Delete', true), array('controller' => 'attributes', 'action' => 'delete', $attribute['id']), null, sprintf(__('Are you sure you want to delete # %s?', true), $attribute['id'])); 
    				} ?>
    			</td>
    		</tr>
    	    <?php endforeach; ?>
    	<?php endforeach; ?>
    	</table>

        <?php endif; ?>
    	<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
    	<div class="actions">
    		<ul>
    			<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']));?> </li>
    			<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']));?> </li>
    		</ul>
    	</div>
    	<?php endif; ?>
    </div>

</div>

<div class="actions">
	<ul>
	<?php if ($isAdmin || $event['Event']['org'] == $me['org']): ?>
    	<li><?php echo $this->Html->link(__('Add Attribute', true), array('controller' => 'attributes', 'action' => 'add', $event['Event']['id']));?> </li>
		<li><?php echo $this->Html->link(__('Add Attachment', true), array('controller' => 'attributes', 'action' => 'add_attachment', $event['Event']['id']));?> </li>
		<li><?php echo $this->Html->link(__('Edit Event', true), array('action' => 'edit', $event['Event']['id'])); ?> </li>
		<li><?php echo $this->Form->postLink(__('Delete Event'), array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id'])); ?></li>
		<li>&nbsp;</li>
	<?php endif; ?>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

