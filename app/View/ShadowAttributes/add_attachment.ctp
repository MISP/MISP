<div class="shadow_attributes form">
<?php echo $this->Form->create('ShadowAttribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");'));?>
	<fieldset>
			<legend><?php echo __('Add Attachment'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
				echo $this->Form->input('category', array(
				'after' => $this->Html->div('forminfo', '', array('id' => 'ShadowAttributeCategoryDiv')),
				'empty' => '(choose one)',
				'div' => 'input'
				));
		?>
			<div class="input clear">
		<?php
		echo $this->Form->file('value', array(
			'error' => array('escape' => false),
		));
		?>
			</div>
			<div class="input clear"><br /></div>
			<div class="input clear"></div>
		<?php
		echo $this->Form->input('malware', array(
				'type' => 'checkbox',
				'checked' => false,
		));
		?>
		<div class="forminfo input clear">
			Tick this box to neutralize the sample. Every malware sample will be zipped with the password "infected"
		</div>
		<?php
		// link an onchange event to the form elements
		$this->Js->get('#ShadowAttributeType')->event('change', 'showFormInfo("#ShadowAttributeType")');
		$this->Js->get('#ShadowAttributeCategory')->event('change', 'showFormInfo("#ShadowAttributeCategory")');
	?>
	</fieldset>
<?php
	echo $this->Form->button('Propose', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>
<?php 
	$event['Event']['id'] = $this->request->data['ShadowAttribute']['event_id'];
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'proposeAttachment', 'event' => $event));
?>
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
