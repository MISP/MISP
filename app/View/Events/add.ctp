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
		if ('true' == Configure::read('CyDefSIG.sync')) {
			echo $this->Form->input('distribution', array(
					'options' => array($distributionLevels),
					'label' => 'Distribution',
					'selected' => $initialDistribution,
					));
		}
		echo $this->Form->input('risk', array(
				'div' => 'input clear'
				));
		echo $this->Form->input('analysis', array(
				'options' => array($analysisLevels),
				));
		echo $this->Form->input('info', array(
				'div' => 'clear',
				'class' => 'input-xxlarge'
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
		'EventRisk' : new Array(),
		'EventAnalysis' : new Array()
};

<?php
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventDistribution']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($riskDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventRisk']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($analysisDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventAnalysis']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
?>

$(document).ready(function() {

	$("#EventAnalysis, #EventRisk, #EventDistribution").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});

	$("#EventAnalysis, #EventRisk, #EventDistribution").on('mouseover', function(e) {
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
	$("#EventAnalysis, #EventRisk, #EventDistribution").on('change', function(e) {
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
