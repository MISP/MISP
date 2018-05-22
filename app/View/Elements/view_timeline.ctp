<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
?>

<div>
	<div class="eventgraph_header">
		<label id="timeline-scope" class="btn center-in-network-header network-control-btn">
			<span class="useCursorPointer fa fa-object-group" style="margin-right: 3px;">
			</span><?php echo __('Time scope')?>
			<span id="timeline-scope-badge" class="badge"></span>
		</label>
		<label id="timeline-display" class="btn center-in-network-header network-control-btn"><span class="useCursorPointer fa fa-list-alt" style="margin-right: 3px;"></span><?php echo __('Display')?></label>
				
		<input type="text" id="timeline-typeahead" class="center-in-network-header network-typeahead flushright" data-provide="typeahead" size="20" placeholder="Search for an item">
	</div>


	<div id="event_timeline" data-user-manipulation="<?php echo $mayModify || $isSiteAdmin ? 'true' : 'false'; ?>">
		<div class="loadingTimeline">
			<div class="spinner"></div>
			<div class="loadingText"><?php echo __('Loading');?></div>
		</div>
	</div>
	<span id="fullscreen-btn-timeline" class="fullscreen-btn-timeline btn btn-xs btn-primary" data-toggle="tooltip" data-placement="top" data-title="<?php echo __('Toggle fullscreen');?>"><span class="fa fa-desktop"></span></span>
</div>

<?php 
	echo $this->Html->script('event-timeline');
	echo $this->Html->css('event-timeline');
?>
