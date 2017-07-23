<div class="dashboard_element w-2 h-1 dashboard_notifications">
	<h4>Changes since last visit</h4>
	<p>
		<b>Events updated: </b><span class="bold <?php echo $events['changed'] ? 'red' : 'green'; ?>"><?php echo h($events['changed']);?></span> (<a href="<?php echo $baseurl;?>/events/index">View</a>)<br />
		<b>Events published: </b><span class="bold <?php echo $events['published'] ? 'red' : 'green'; ?>"><?php echo h($events['published']);?></span> (<a href="<?php echo $baseurl;?>/events/index">View</a>)<br />
	</p>
	<?php echo $this->Form->postLink('Reset', $baseurl . '/users/updateLoginTime', array('div' => false));?>
</div>
<script type="text/javascript">
$(document).ready(function() {
	var elem = $('.dashboard_notifications').width();
	$('.dashboard_notifications').css({'height':elem+'px'});
});
</script>
