<?php 
	echo $this->Html->script('d3.v3.min');
	echo $this->Html->script('cal-heatmap.min');
	echo $this->Html->css('cal-heatmap');
?>
<div class = "index">
<h2>Statistics</h2>
<p>Some statistics about this instance. The changes since the beginning of this month are noted in brackets wherever applicable</p>
<dl style="width:250px;">
	<dt><?php echo 'Events'; ?></dt>
	<dd><?php echo h($stats[0]);
		if ($stats[1]) echo ' <span style="color:green">(+' . h($stats[1]) . ')</span>&nbsp;';
		else echo ' <span style="color:red">(0)</span>&nbsp;';?>
	</dd>
	<dt><?php echo 'Attributes'; ?></dt>
	<dd><?php echo h($stats[2]);
		if ($stats[1]) echo ' <span style="color:green">(+' . h($stats[3]) . ')</span>&nbsp;';
		else echo ' <span style="color:red">(0)</span>&nbsp;';?>
	</dd>
	<dt><?php echo 'Correlations found'; ?></dt>
	<dd><?php echo h($stats[4]); ?>&nbsp;</dd>
	<dt><?php echo 'Proposals active'; ?></dt>
	<dd><?php echo h($stats[5]); ?>&nbsp;</dd>
	<dt><?php echo 'Users'; ?></dt>
	<dd><?php echo h($stats[6]); ?>&nbsp;</dd>
	<dt><?php echo 'Organisations'; ?></dt>
	<dd><?php echo h($stats[7]); ?>&nbsp;</dd>
	<dt><?php echo 'Discussion threads'; ?></dt>
	<dd><?php echo h($stats[8]);
		if ($stats[9]) echo ' <span style="color:green">(+' . h($stats[9]) . ')</span>&nbsp;';
		else echo ' <span style="color:red">(0)</span>&nbsp;';?>
	</dd>
	<dt><?php echo 'Discussion posts'; ?></dt>
	<dd><?php echo h($stats[10]);
		if ($stats[11]) echo ' <span style="color:green">(+' . h($stats[11]) . ')</span>&nbsp;';
		else echo ' <span style="color:red">(0)</span>&nbsp;';?>
	</dd>
</dl>
<br />
<h3>Activity Heatmap</h3>
<p>A heatmap showing user activity for each day during this month and the 4 months that preceded it. Use the buttons below to only show the heatmap of a specific organisation.</p>
<div id="orgs">
	<ul class="inline">
	<li id="org-all"  class="btn btn btn.active qet" style="margin-right:5px;" onClick="updateCalendar('all')">All organisations</li>
	<?php 
		foreach($orgs as $org): ?>
			<li id="org-<?php echo $org['User']['org'];?>"  class="btn btn btn.active qet" style="margin-right:5px;" onClick="updateCalendar('<?php echo $org['User']['org'];?>')">
				<?php echo $org['User']['org'];?>
			</li>
	<?php 
		endforeach;	
	?>
	</ul>
</div>
<br />
<br />
<div id="cal-heatmap"></div>


<script type="text/javascript">
var cal = new CalHeatMap();
cal.init({
	range: 5, 
	domain:"month", 
	subDomain:"x_day",
	start: new Date(<?php echo $startDateCal; ?>),
	data: "<?php echo Configure::read('CyDefSIG.baseurl'); ?>/logs/returnDates/<?php echo $start; ?>/<?php echo $end?>.json",
	highlight: "now",
	domainDynamicDimension: false,
	cellSize: 20,
	cellPadding: 1,
	domainGutter: 10,
	//subDomainTextFormat: "%d",
	legend: [20, 40, 60, 80],
	legendCellSize: 15
});

function updateCalendar(org) {
	if (org == 'all') {
		cal.update("<?php echo Configure::read('CyDefSIG.baseurl'); ?>/logs/returnDates/<?php echo $start; ?>/<?php echo $end?>/all.json");
	} else {
		cal.update("<?php echo Configure::read('CyDefSIG.baseurl'); ?>/logs/returnDates/<?php echo $start; ?>/<?php echo $end?>/"+org+".json");
	}
}
</script>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>