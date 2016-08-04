<div class="users index">
	<div id = "histogram"></div>
	<?php //echo $this->element('histogram');?>
<br /><br />
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'members'));
?>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
	updateHistogram('');
});
</script>
