<div class="shadowAttributes form">
<?php echo $this->Form->create('ShadowAttribute');?>
	<fieldset>
		<legend><?php echo __('Edit Attribute'); ?></legend>
<?php
echo $this->Form->input('id');
echo $this->Form->input('category', array('between' => $this->Html->div('forminfo', '', array('id' => 'ShadowAttributeCategoryDiv'))));
if (!$attachment) {
	echo $this->Form->input('type', array('between' => $this->Html->div('forminfo', '', array('id' => 'ShadowAttributeTypeDiv'))));
}
echo $this->Form->input('to_ids', array(
			'before' => $this->Html->div('forminfo', isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc']),
			'label' => 'IDS Signature?'
));
if (!$attachment) {
	echo $this->Form->input('value', array(
			'type' => 'textarea',
			'error' => array('escape' => false),
	));
}

$this->Js->get('#ShadowAttributeCategory')->event('change', 'formCategoryChanged("#ShadowAttributeCategory")');
$this->Js->get('#ShadowAttributeType')->event('change', 'showFormInfo("#ShadowAttributeType")');
?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
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
	var options = $('#ShadowAttributeType').prop('options');
	$('option', $('#ShadowAttributeType')).remove();
	$.each(category_type_mapping[$('#ShadowAttributeCategory').val()], function(val, text) {
		options[options.length] = new Option(text, val);
	});
	// enable the form element
	$('#ShadowAttributeType').prop('disabled', false);
}


//
//Generate tooltip information
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
?>

function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();	// get the selected value
	$(idDiv).html(formInfoValues[value]);	// search in a lookup table

	// show it again
	$(idDiv).fadeIn('slow');
}

//hide the formInfo things
$('#ShadowAttributeTypeDiv').hide();
$('#ShadowAttributeCategoryDiv').hide();
// fix the select box based on what was selected
var type_value = $('#ShadowAttributeType').val();
formCategoryChanged("#ShadowAttributeCategory");
$('#ShadowAttributeType').val(type_value);

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
