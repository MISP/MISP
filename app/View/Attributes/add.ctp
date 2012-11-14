
<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Add Attribute'); ?></legend>
<?php
echo $this->Form->hidden('event_id');
echo $this->Form->input('category', array(
		'between' => $this->Html->div('forminfo', '', array('id' => 'AttributeCategoryDiv')),
		'empty' => '(choose one)'
		));
echo $this->Form->input('type', array(
		'between' => $this->Html->div('forminfo', '', array('id' => 'AttributeTypeDiv')),
		'empty' => '(first choose category)'
		));
if ('true' == Configure::read('CyDefSIG.sync')) {
	if ('true' == Configure::read('CyDefSIG.private')) {
		echo $this->Form->input('distribution', array('label' => 'Distribution', 'selected' => 'All',
			'between' => $this->Html->div('forminfo', '', array('id' => 'AttributeDistributionDiv'))
		));
	} else {
		echo $this->Form->input('private', array(
			'before' => $this->Html->div('forminfo', isset($attrDescriptions['private']['formdesc']) ? $attrDescriptions['private']['formdesc'] : $attrDescriptions['private']['desc']),
		));
	}
}
echo $this->Form->input('to_ids', array(
			'checked' => true,
			'before' => $this->Html->div('forminfo', isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc']),
			'label' => 'IDS Signature?'
));
echo $this->Form->input('value', array(
			'type' => 'textarea',
			'error' => array('escape' => false),
));
echo $this->Form->input('batch_import', array(
			'type' => 'checkbox',
			'after' => $this->Html->div('forminfo', 'Create multiple attributes one per line'),
));

// link an onchange event to the form elements
$this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("#AttributeCategory")');
$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
$this->Js->get('#AttributeDistribution')->event('change', 'showFormInfo("#AttributeDistribution")');
?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
<script type="text/javascript">
//
//Generate Category / Type filtering array
//
var category_type_mapping = new Array();
<?php
foreach ($categoryDefinitions as $category => $def) {
	echo "category_type_mapping['" . addslashes($category) . "'] = {";
	$first = true;
	foreach ($def['types'] as $type) {
		if ($first) $first = false;
		else echo ', ';
		echo "'" . addslashes($type) . "' : '" . addslashes($type) . "'";
	}
	echo "}; \n";
}
?>

function formCategoryChanged(id) {
	showFormInfo(id); // display the tooltip
	// fill in the types
	var options = $('#AttributeType').prop('options');
	$('option', $('#AttributeType')).remove();
	$.each(category_type_mapping[$('#AttributeCategory').val()], function(val, text) {
		options[options.length] = new Option(text, val);
	});
	// enable the form element
	$('#AttributeType').prop('disabled', false);
}


//
// Generate tooltip information
//
var formInfoValues = new Array();
<?php
foreach ($typeDefinitions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
}
foreach ($categoryDefinitions as $category => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($category) . "'] = \"" . addslashes($info) . "\";\n"; // as we output JS code we need to add slashes
}
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
$('#AttributeTypeDiv').hide();
$('#AttributeCategoryDiv').hide();
$('#AttributeType').prop('disabled', true);
$('#AttributeDistributionDiv').hide();


</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts