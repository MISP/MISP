<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
?>

<div id="eventdistri_graph" style="height: 400px; width: 400px;" data-event-id="<?php echo h($event['Event']['id']); ?>" data-user-manipulation="<?php echo $mayModify || $isSiteAdmin ? 'true' : 'false'; ?>" data-extended="<?php echo $extended; ?>">
    <canvas id="distribution_graph_canvas" width="100" height="100" ></canvas>
</div>

<?php
	echo $this->Html->script('Chart.min');
	echo $this->Html->script('event-distribution-graph');
?>
