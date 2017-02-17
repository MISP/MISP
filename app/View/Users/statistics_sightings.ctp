<div class = "index">
	<h2>Statistics</h2>
	<?php
		echo $this->element('Users/statisticsMenu');
	?>
	<p>A toplist of the top sources for the sightings of your organisation.</p>
	<table class="table table-striped table-hover table-condensed" style="display:block; overflow-y:auto;width:700px;">
	<tr>
      <th>Source</th>
			<th>#Entries</th>
			<th>#Sighting</th>
      <th>#False-positive</th>
      <th>Expiration</th>
	</tr>
	<?php
		$count = 0;
		foreach ($toplist as $source => $total):
			if ($count > 9) break;
	?>
			<tr>
				<td style="width:20%;"><?php echo empty($source) ? 'Undefined' : h($source);?></td>
				<td style="width:20%;"><?php echo h($total);?></td>
				<td style="width:20%;"><?php echo isset($data[$source][0]) ? h($data[$source][0]) : 0;?></td>
				<td style="width:20%;"><?php echo isset($data[$source][1]) ? h($data[$source][1]) : 0;?></td>
				<td style="width:20%;"><?php echo isset($data[$source][2]) ? h($data[$source][2]) : 0;?></td>

			</tr>
	<?php
			$count++;
		endforeach;
	?>
	</table>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
<script type="text/javascript">
$(document).ready(function () {
	loadSightingsData();
});
</script>
