<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Edit Event'); ?></legend>
<?php
echo $this->Form->input('id');
echo $this->Form->input('date');
echo $this->Form->input('risk', array(
		'before' => $this->Html->div('forminfo', isset($eventDescriptions['risk']['formdesc']) ? $eventDescriptions['risk']['formdesc'] : $eventDescriptions['risk']['desc'])));
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
?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<ul>

		<li><?php echo $this->Html->link(__('Delete', true), array('action' => 'delete', $this->Form->value('Event.id')), null, sprintf(__('Are you sure you want to delete # %s?', true), $this->Form->value('Event.id'))); ?></li>
		<li>&nbsp;</li>
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
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
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
</script>
<?php echo $this->Js->writeBuffer();