
<div class="shadow_attributes form">
<?php echo $this->Form->create('ShadowAttribute');?>
	<fieldset>
		<legend><?php echo __('Add ShadowAttribute'); ?></legend>
<?php
echo $this->Form->hidden('event_id');
echo $this->Form->input('category', array(
		'between' => $this->Html->div('forminfo', '', array('id' => 'ShadowAttributeCategoryDiv')),
		'empty' => '(choose one)'
		));
echo $this->Form->input('type', array(
		'between' => $this->Html->div('forminfo', '', array('id' => 'ShadowAttributeTypeDiv')),
		'empty' => '(first choose category)'
		));
echo $this->Form->input('to_ids', array(
			'checked' => true,
			'before' => $this->Html->div('forminfo', isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc']),
			'label' => 'IDS Signature?'
));
echo $this->Form->input('batch_import', array(
		'type' => 'checkbox',
		'after' => $this->Html->div('forminfo', 'Create multiple attributes one per line'),
));
echo $this->Form->input('value', array(
			'type' => 'textarea',
			'error' => array('escape' => false),
));

// link an onchange event to the form elements
$this->Js->get('#ShadowAttributeCategory')->event('change', 'formCategoryChanged("#ShadowAttributeCategory")');
$this->Js->get('#ShadowAttributeType')->event('change', 'showFormInfo("#ShadowAttributeType")');
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
	var options = $('#ShadowAttributeType').prop('options');
	$('option', $('#ShadowAttributeType')).remove();
	$.each(category_type_mapping[$('#ShadowAttributeCategory').val()], function(val, text) {
		options[options.length] = new Option(text, val);
	});
	// enable the form element
	$('#ShadowAttributeType').prop('disabled', false);
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
$('#ShadowAttributeTypeDiv').hide();
$('#ShadowAttributeCategoryDiv').hide();
$('#ShadowAttributeType').prop('disabled', true);


</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts