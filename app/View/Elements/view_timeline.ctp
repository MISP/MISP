<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
?>

<div>
	<div id="event_timeline">
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
