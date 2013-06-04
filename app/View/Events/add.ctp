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
					'selected' => 'All communities',
					'after' => $this->Html->div('forminfo', '', array('id' => 'EventDistributionDiv')),
					));
		}
		echo $this->Form->input('risk', array(
				'after' => $this->Html->div('forminfo', '', array('id' => 'EventRiskDiv')),
				'div' => 'input clear'
				));
		echo $this->Form->input('analysis', array(
				'options' => array($analysisLevels),
				'after' => $this->Html->div('forminfo', '', array('id' => 'EventAnalysisDiv'))
				));
		echo $this->Form->input('info', array(
				'div' => 'clear',
				'class' => 'input-xxlarge'
				));
		echo $this->Form->input('Event.submittedgfi', array(
				'label' => '<b>GFI sandbox</b>',
				'type' => 'file',
				// 'between' => $this->Html->div('forminfo', isset($eventDescriptions['submittedgfi']['formdesc']) ? $eventDescriptions['submittedgfi']['formdesc'] : $eventDescriptions['submittedgfi']['desc']),
				'div' => 'clear'
				));
		// link an onchange event to the form elements
		$this->Js->get('#EventDistribution')->event('change', 'showFormInfo("#EventDistribution")');
		$this->Js->get('#EventRisk')->event('change', 'showFormInfo("#EventRisk")');
		$this->Js->get('#EventAnalysis')->event('change', 'showFormInfo("#EventAnalysis")');
		?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>

<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li class="active"><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Attributes', array('controller' => 'attributes', 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link('Search Attributes', array('controller' => 'attributes', 'action' => 'search')); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Export', array('controller' => 'events', 'action' => 'export')); ?> </li>
		<?php if ($isAclAuth): ?>
		<li><?php echo $this->Html->link('Automation', array('controller' => 'events', 'action' => 'automation')); ?></li>
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
