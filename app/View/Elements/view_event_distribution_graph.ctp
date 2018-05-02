<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
?>

<div id="distribution_graph_container">
	<div class="loadingPopover">
		<div class="spinner"></div>
		<div class="loadingText"><?php echo __('Loading');?></div>
	</div>
	<div id="eventdistri_graph" data-event-id="<?php echo h($event['Event']['id']); ?>" data-event-distribution="<?php echo h($event['Event']['distribution']); ?>" data-user-manipulation="<?php echo $mayModify || $isSiteAdmin ? 'true' : 'false'; ?>" data-extended="<?php echo $extended; ?>">
		<canvas id="distribution_graph_canvas" 	height="360px"width="400px"></canvas>
	</div>
	<div id="eventdistri_pb_container">
		<div id="eventdistri_pb_background" class="customProgress useCursorPointer">
			<div id="eventdistri_pb_min" class="customProgress useCursorPointer animatedPB" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" data-toggle="tooltip" data-placement="left" data-container="body" title="<?php echo __('Elements having lower distribution level than the event distribution'); ?>"></div>
			<div id="eventdistri_pb" class="customProgress useCursorPointer animatedPB" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" data-toggle="tooltip" data-placement="top" data-container="body" title="<?php echo __('Event distribution'); ?>"></div>
			<div id="eventdistri_pb_invalid" class="customProgress useCursorPointer animatedPB" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" data-toggle="tooltip" data-placement="right" data-container="body" title="<?php echo __('Maximum level of non distributed elements'); ?>"></div>
		</div>
	</div>
	<div id="eventdistri_sg_pb_container">
		<span class="sharingGroup_pb_text useCursorPointer badge"><?php echo __("Sharing group"); ?></span>
		<div id="eventdistri_sg_pb_background" class="customProgress useCursorPointer">
			<div id="eventdistri_sg_pb" class="customProgress useCursorPointer animatedPB" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" data-toggle="tooltip" data-placement="top" data-container="body" title="<?php echo __('Sharing group'); ?>"></div>
		</div>
	</div>
</div>

<?php
	echo $this->Html->script('Chart.min');
	echo $this->Html->script('event-distribution-graph');
	echo $this->Html->css('distribution-graph');
?>
