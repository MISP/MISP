<?php 
	echo $this->Html->script('d3.v3.min');
	echo $this->Html->script('cal-heatmap.min');
	echo $this->Html->css('cal-heatmap');
?>
<div class = "index">
<h3>Orgs</h3>
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
<h3>Activity heatmap</h3>
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