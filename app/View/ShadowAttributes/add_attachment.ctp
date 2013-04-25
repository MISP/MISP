<div class="shadow_attributes form">
<?php echo $this->Form->create('ShadowAttribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");'));?>
	<fieldset>
			<legend><?php echo __('Add Attachment'); ?></legend>
<?php
echo $this->Form->hidden('event_id');
echo $this->Form->input('category', array('between' => $this->Html->div('forminfo', '', array('id' => 'ShadowAttributeCategoryDiv'))));
echo $this->Form->file('value', array(
	'error' => array('escape' => false),
));
echo $this->Form->input('malware', array(
		'type' => 'checkbox',
		'checked' => false,
		'after' => '<br>Tick this box to neutralize the sample. Every malware sample will be zipped with the password "infected"',
));
// link an onchange event to the form elements
$this->Js->get('#ShadowAttributeType')->event('change', 'showFormInfo("#ShadowAttributeType")');
$this->Js->get('#ShadowAttributeCategory')->event('change', 'showFormInfo("#ShadowAttributeCategory")');
?>
	</fieldset>
<?php echo $this->Form->end(__('Upload'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

<script type="text/javascript">
var formInfoValues = new Array();
<?php
foreach ($categoryDefinitions as $category => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['$category'] = \"$info\";\n";
}
?>

var formZipTypeValues = new Array();
<?php
foreach ($categoryDefinitions as $category => $def) {
	$types = $def['types'];
	$alreadySet = false;
	foreach ($types as $type) {
		if (in_array($type, $zippedDefinitions) && !$alreadySet) {
			$alreadySet = true;
			echo "formZipTypeValues['$category'] = \"true\";\n";
		}
	}
	if (!$alreadySet) {
		echo "formZipTypeValues['$category'] = \"false\";\n";
	}
}
?>

var formAttTypeValues = new Array();
<?php
foreach ($categoryDefinitions as $category => $def) {
	$types = $def['types'];
	$alreadySet = false;
	foreach ($types as $type) {
		if (in_array($type, $uploadDefinitions) && !$alreadySet) {
			$alreadySet = true;
			echo "formAttTypeValues['$category'] = \"true\";\n";
		}
	}
	if (!$alreadySet) {
		echo "formAttTypeValues['$category'] = \"false\";\n";
	}
}
?>

function showFormType(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();	// get the selected value
	//$(idDiv).html(formInfoValues[value]);	// search in a lookup table

	// do checkbox un/ticked when the document is changed
	if (formZipTypeValues[value] == "true") {
		document.getElementById("ShadowAttributeMalware").setAttribute("checked", "checked");
		if (formAttTypeValues[value] == "false") document.getElementById("ShadowAttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");
	} else {
		document.getElementById("ShadowAttributeMalware").removeAttribute("checked");
		if (formAttTypeValues[value] == "true") document.getElementById("ShadowAttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");
	}
}

function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();	// get the selected value
	$(idDiv).html(formInfoValues[value]);	// search in a lookup table

	// show it again
	$(idDiv).fadeIn('slow');

	// do checkbox un/ticked when the document is changed
	if (formZipTypeValues[value] == "true") {
		document.getElementById("ShadowAttributeMalware").setAttribute("checked", "checked");
		if (formAttTypeValues[value] == "false") document.getElementById("ShadowAttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");
	} else {
		document.getElementById("ShadowAttributeMalware").removeAttribute("checked");
		if (formAttTypeValues[value] == "true") document.getElementById("ShadowAttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");
	}
}

// hide the formInfo things
$('#ShadowAttributeTypeDiv').hide();
$('#ShadowAttributeCategoryDiv').hide();
$(function(){
	// do checkbox un/ticked when the document is ready
	showFormType("#ShadowAttributeCategory");
	}
);

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts