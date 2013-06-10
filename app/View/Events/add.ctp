<div class="events form">
<?php echo $this->Form->create('', array('type' => 'file'));?>
	<fieldset>
		<legend>Add Event</legend>
		<?php
		echo $this->Form->input('date', array(
				'type' => 'text',
				'class' => 'datepicker'
		));
		if ('true' == Configure::read('CyDefSIG.sync')) {
			echo $this->Form->input('distribution', array(
					'label' => 'Distribution',
					'selected' => 'All communities'
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

<div class="actions">
	<ul class="nav nav-list">
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li class="active"><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/attributes/index">List Attributes</a></li>
		<li><a href="/attributes/search">Search Attributes</a></li>
		<li class="divider"></li>
		<li><a href="/events/export">Export</a></li>
		<?php if ($isAclAuth): ?>
		<li><a href="/events/automation">Automation</a></li>
		<?php endif;?>
	</ul>
</div>

<script type="text/javascript">
//
//Generate tooltip information
//
var formInfoValues = new Array();
<?php
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($riskDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($analysisDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
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
	            trigger: 'manual',
	            placement: 'right',
	            content: formInfoValues[$e.val()],
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
            trigger: 'manual',
            placement: 'right',
            content: formInfoValues[$e.val()],
        }).popover('show');
	});
});

</script>
<?php echo $this->Js->writeBuffer();
