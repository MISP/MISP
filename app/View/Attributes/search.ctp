<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Search Attribute'); ?></legend>
	<?php
		echo $this->Form->input('keyword', array('type' => 'textarea', 'label' => 'Containing the following expressions'));
		echo $this->Form->input('keyword2', array('type' => 'textarea', 'label' => 'Excluding the following events'));
		echo $this->Form->input('org', array('type' => 'text', 'label' => 'From the following organisation'));
		echo $this->Form->input('type', array('between' => $this->Html->div('forminfo', '', array('id' => 'AttributeTypeDiv'))));
		echo $this->Form->input('category', array('between' => $this->Html->div('forminfo', '', array('id' => 'AttributeCategoryDiv'))));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Search', true));?>
</div>
<script type="text/javascript">
//
//Generate Category / Type filtering array
//
var category_type_mapping = new Array();

<?php
// all types for Categorie ALL
echo "category_type_mapping['ALL'] = {";
$first = true;
foreach ($typeDefinitions as $type => $def) {
		if ($first) $first = false;
		else echo ', ';
		echo "'" . addslashes($type) . "' : '" . addslashes($type) . "'";
}
echo "}; \n";

//all types for empty Categorie
echo "category_type_mapping[''] = {";
$first = true;
foreach ($typeDefinitions as $type => $def) {
		if ($first) $first = false;
		else echo ', ';
		echo "'" . addslashes($type) . "' : '" . addslashes($type) . "'";
}
echo "}; \n";

// Types per Categorie
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

//
//Generate Type / Category filtering array
//
var type_category_mapping = new Array();

<?php
// all categories for Type ALL
echo "type_category_mapping['ALL'] = {";
$first = true;
foreach ($categoryDefinitions as $type => $def) {
		if ($first) $first = false;
		else echo ', ';
		echo "'" . addslashes($type) . "' : '" . addslashes($type) . "'";
}
echo "}; \n";

// Categories per Type
foreach ($typeDefinitions as $type => $def) {
	echo "type_category_mapping['" . addslashes($type) . "'] = {";
	$first = true;
	foreach ($categoryDefinitions as $category => $def) {
		if ( in_array ( $type , $def['types'])) {
			if ($first) $first = false;
			else echo ', ';
			echo "'" . addslashes($category) . "' : '" . addslashes($category) . "'";
		}
	}
	echo "}; \n";
}
?>

function formCategoryChanged(id) {
	var alreadySelected = $('#AttributeType').val();
	showFormInfo(id); // display the tooltip
	// empty the types
	document.getElementById("AttributeType").options.length = 1;
	// add new items to options
	var options = $('#AttributeType').prop('options');
	$.each(category_type_mapping[$('#AttributeCategory').val()], function(val, text) {
		options[options.length] = new Option(text, val);
		if (val == alreadySelected) {
			options[options.length-1].selected = true;
		}
	});
	// enable the form element
	$('#AttributeType').prop('disabled', false);
	if ("ALL" == $('#AttributeCategory').val()) {
		//alert($('#AttributeCategory').val());
		$('#AttributeCategoryDiv').hide();
	}
}

function formTypeChanged(id) {
	var alreadySelected = $('#AttributeCategory').val();
	showFormInfo(id); // display the tooltip
	// empty the categories
	document.getElementById("AttributeCategory").options.length = 2;
	// add new items to options
	var options = $('#AttributeCategory').prop('options');
	$.each(type_category_mapping[$('#AttributeType').val()], function(val, text) {
		options[options.length] = new Option(text, val);
		if (val == alreadySelected) {
			options[options.length-1].selected = true;
		}
	});
	// enable the form element
	$('#AttributeCategory').prop('disabled', false);
	if ("ALL" == $('#AttributeType').val()) {
		//alert($('#AttributeType').val());
		$('#AttributeTypeDiv').hide();
	}
}

var formInfoValues = new Array();
<?php
foreach ($typeDefinitions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['$type'] = \"$info\";\n";
}

foreach ($categoryDefinitions as $category => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['$category'] = \"$info\";\n";
}
$this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("#AttributeCategory")');
$this->Js->get('#AttributeCategory')->event('change', 'showFormInfo("#AttributeCategory")');
$this->Js->get('#AttributeType')->event('change', 'formTypeChanged("#AttributeType")');
$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
?>

formInfoValues['ALL'] = '';
formInfoValues[''] = '';

function showFormInfo(id) {
	idDiv = id+'Div';
	if (("ALL" != $(id).val()) && ("" != $(id).val())) {
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();    // get the selected value
	$(idDiv).html(formInfoValues[value]);    // search in a lookup table

	// show it again
	$(idDiv).fadeIn('slow');
	} else {
		$(idDiv).hide();
	}
}

// hide the formInfo things
$('#AttributeTypeDiv').hide();
$('#AttributeCategoryDiv').hide();

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts