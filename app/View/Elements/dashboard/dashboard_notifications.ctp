<div class="dashboard_element w-2 h-1 dashboard_notifications">
	<h4>Notifications</h4>
	<p>
		<b>Proposals: </b><span class="bold <?php echo $notifications['proposalCount'] ? 'red' : 'green'; ?>"><?php echo h($notifications['proposalCount']);?></span> (<a href="<?php echo $baseurl;?>/shadow_attributes/index">View</a>)<br />
		<b>Events with proposals: </b><span class="bold <?php echo $notifications['proposalEventCount'] ? 'red' : 'green'; ?>"><?php echo h($notifications['proposalEventCount']);?></span> (<a href="<?php echo $baseurl;?>/events/proposalEventIndex">View</a>)<br />
		<b>Delegation requests: </b><span class="bold <?php echo $notifications['delegationCount'] ? 'red' : 'green'; ?>"><?php echo h($notifications['delegationCount']);?></span> (<a href="<?php echo $baseurl;?>/events/delegation_index">View</a>)
	</p>
</div>
<script type="text/javascript">
$(document).ready(function() {
	var elem = $('.dashboard_notifications').width();
	$('.dashboard_notifications').css({'height':elem+'px'});
});
</script>