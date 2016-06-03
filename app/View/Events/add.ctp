<div class="events form">
<?php echo $this->Form->create('', array('type' => 'file'));?>
	<fieldset>
		<legend>Add Event</legend>
		<?php
		echo $this->Form->input('date', array(
				'type' => 'text',
				'class' => 'datepicker'
		));
		$initialDistribution = 3;
		if (Configure::read('MISP.default_event_distribution') != null) {
			$initialDistribution = Configure::read('MISP.default_event_distribution');
		}
		echo $this->Form->input('distribution', array(
				'options' => array($distributionLevels),
				'div' => 'input clear',
				'label' => 'Distribution',
				'selected' => $initialDistribution,
			));
		?>
			<div id="SGContainer" style="display:none;">
		<?php
		if (!empty($sharingGroups)) {
			echo $this->Form->input('sharing_group_id', array(
					'options' => array($sharingGroups),
					'label' => 'Sharing Group',
			));
		}
		?>
			</div>
		<?php
		echo $this->Form->input('threat_level_id', array(
				'div' => 'input clear',
				'selected' => Configure::read('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : '1',
				));
		echo $this->Form->input('analysis', array(
				'options' => array($analysisLevels),
				));
		echo $this->Form->input('info', array(
					'label' => 'Event Info',
					'div' => 'clear',
					'type' => 'text',
					'class' => 'form-control span6',
					'placeholder' => 'Quick Event Description or Tracking Info'
				));
		echo $this->Form->input('Event.submittedgfi', array(
				'label' => '<b>GFI sandbox</b>',
				'type' => 'file',
				'div' => 'clear'
				));
		?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>

<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'add'));
?>

<script type="text/javascript">
//
//Generate tooltip information
//
var formInfoValues = {
		'EventDistribution' : new Array(),
		'EventThreatLevelId' : new Array(),
		'EventAnalysis' : new Array()
};

<?php
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventDistribution']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($riskDescriptions as $type => $def) {
	echo "formInfoValues['EventThreatLevelId']['" . addslashes($type) . "'] = \"" . addslashes($def) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($analysisDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventAnalysis']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
?>

$('#EventDistribution').change(function() {
	if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
	else $('#SGContainer').hide();
});

$(document).ready(function() {

	if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
	else $('#SGContainer').hide();

	$("#EventAnalysis, #EventThreatLevelId, #EventDistribution").on('mouseover', function(e) {
	    var $e = $(e.target);
	    if ($e.is('option')) {
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'focus',
	            placement: 'right',
	            content: formInfoValues[e.currentTarget.id][$e.val()],
	        }).popover('show');
		}
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#EventAnalysis, #EventThreatLevelId, #EventDistribution").on('change', function(e) {
		var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'focus',
            placement: 'right',
            content: formInfoValues[e.currentTarget.id][$e.val()],
        }).popover('show');
	});
});

</script>
<?php echo $this->Js->writeBuffer();
