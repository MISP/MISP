<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Edit Event'); ?></legend>
<?php
echo $this->Form->input('id');
echo $this->Form->input('date');
echo $this->Form->input('risk', array(
		'before' => $this->Html->div('forminfo', '', array('id' => 'EventRiskDiv'))));
echo $this->Form->input('analysis', array(
		'options' => array($analysisLevels),
		'before' => $this->Html->div('forminfo', '', array('id' => 'EventAnalysisDiv'))));
if ('true' == Configure::read('CyDefSIG.sync')) {
	if ('true' == Configure::read('CyDefSIG.private')) {
		echo $this->Form->input('distribution', array('label' => 'Distribution',
			'between' => $this->Html->div('forminfo', '', array('id' => 'EventDistributionDiv'))
		));
	} else {
		echo $this->Form->input('private', array(
			'before' => $this->Html->div('forminfo', isset($eventDescriptions['private']['formdesc']) ? $eventDescriptions['private']['formdesc'] : $eventDescriptions['private']['desc']),));
	}
}
echo $this->Form->input('info');

// link an onchange event to the form elements
$this->Js->get('#EventDistribution')->event('change', 'showFormInfo("#EventDistribution")');
$this->Js->get('#EventRisk')->event('change', 'showFormInfo("#EventRisk")');
$this->Js->get('#EventAnalysis')->event('change', 'showFormInfo("#EventAnalysis")');
?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
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

function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();    // get the selected value
	$(idDiv).html(formInfoValues[value]);    // search in a lookup table
	// show it again
	$(idDiv).fadeIn('slow');
}

// hide the formInfo things
$('#EventDistributionDiv').hide();
$('#EventRiskDiv').hide();
$('#EventAnalysisDiv').hide();
</script>
<?php echo $this->Js->writeBuffer();