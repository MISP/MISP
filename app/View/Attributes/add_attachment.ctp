<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("AttributeMalware").removeAttribute("disabled");'));?>
	<fieldset>
			<legend><?php echo __('Add Attachment'); ?></legend>
<?php
echo $this->Form->hidden('event_id');
echo $this->Form->input('category', array('between' => $this->Html->div('forminfo', '', array('id' => 'AttributeCategoryDiv'))));
echo $this->Form->file('value', array(
	'error' => array('escape' => false),
));
echo $this->Form->input('malware', array(
		'type' => 'checkbox',
		'checked' => false,
		'after' => '<br>Tick this box to neutralize the sample. Every malware sample will be zipped with the password "infected"',
));
if ('true' == Configure::read('CyDefSIG.sync')) {
	echo $this->Form->input('private', array(
			'before' => $this->Html->div('forminfo', isset($attr_descriptions['private']['formdesc']) ? $attr_descriptions['private']['formdesc'] : $attr_descriptions['private']['desc']),));
}
// link an onchange event to the form elements
$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
$this->Js->get('#AttributeCategory')->event('change', 'showFormInfo("#AttributeCategory")');
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
foreach ($category_definitions as $category => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['$category'] = \"$info\";\n";
}
?>

var formZipTypeValues = new Array();
<?php
foreach ($category_definitions as $category => $def) {
	$types = $def['types'];
	$alreadySet = false;
	foreach ($types as $type) {
		if (in_array($type, $zipped_definitions) && !$alreadySet) {
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
foreach ($category_definitions as $category => $def) {
	$types = $def['types'];
	$alreadySet = false;
	foreach ($types as $type) {
		if (in_array($type, $upload_definitions) && !$alreadySet) {
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
		document.getElementById("AttributeMalware").setAttribute("checked", "checked");
		if (formAttTypeValues[value] == "false") document.getElementById("AttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("AttributeMalware").removeAttribute("disabled");
	} else {
		document.getElementById("AttributeMalware").removeAttribute("checked");
		if (formAttTypeValues[value] == "true") document.getElementById("AttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("AttributeMalware").removeAttribute("disabled");
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
		document.getElementById("AttributeMalware").setAttribute("checked", "checked");
		if (formAttTypeValues[value] == "false") document.getElementById("AttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("AttributeMalware").removeAttribute("disabled");
	} else {
		document.getElementById("AttributeMalware").removeAttribute("checked");
		if (formAttTypeValues[value] == "true") document.getElementById("AttributeMalware").setAttribute("disabled", "disabled");
		else document.getElementById("AttributeMalware").removeAttribute("disabled");
	}
}

// hide the formInfo things
$('#AttributeTypeDiv').hide();
$('#AttributeCategoryDiv').hide();
$(function(){
	// do checkbox un/ticked when the document is ready
	showFormType("#AttributeCategory");
	}
);

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts