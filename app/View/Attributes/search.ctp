<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend>Search Attribute</legend>
		You can search for attributes based on contained expression within the value, event ID, submiting organisation, category and type. <br />For the value, event ID and organisation, you can enter several search terms by entering each term as a new line. To exclude things from a result, use the NOT operator (!) infront of the term.<br/><br />
		<?php
			echo $this->Form->input('keyword', array('type' => 'textarea', 'label' => 'Containing the following expressions', 'div' => 'clear', 'class' => 'input-xxlarge'));
			echo $this->Form->input('keyword2', array('type' => 'textarea', 'label' => 'Being attributes of the following event IDs', 'div' => 'clear', 'class' => 'input-xxlarge'));
		?>
		<?php
			if ('true' == Configure::read('MISP.showorg') || $isAdmin)
				echo $this->Form->input('org', array(
						'type' => 'textarea',
						'label' => 'From the following organisation(s)',
						'div' => 'input clear',
						'class' => 'input-xxlarge'));
		?>
		<?php
			echo $this->Form->input('type', array(
					'div' => 'input clear',
					));
			echo $this->Form->input('category', array(
					));
		?>
			<div class="input clear"></div>
		<?php
			echo $this->Form->input('ioc', array(
				'type' => 'checkbox',
				'label' => 'Only find valid IOCs',
			));
		?>
	</fieldset>
<?php
echo $this->Form->button('Search', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
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
}

function formTypeChanged(id) {
	var alreadySelected = $('#AttributeCategory').val();
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
$this->Js->get('#AttributeType')->event('change', 'formTypeChanged("#AttributeType")');
?>

formInfoValues['ALL'] = '';
formInfoValues[''] = '';


$(document).ready(function() {

	$("#AttributeType, #AttributeCategory").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});

	$("#AttributeType, #AttributeCategory").on('mouseover', function(e) {
	    var $e = $(e.target);
	    if ($e.is('option')) {
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'manual',
	            placement: 'right',
	            content: formInfoValues[$e.val()],
	        }).popover('show');
	    }
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#AttributeType, #AttributeCategory").on('change', function(e) {
	    var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'manual',
            placement: 'right',
            content: formInfoValues[$e.val()],
        }).popover('show');
	});

});
</script>
<?php 
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'searchAttributes'));
?>
<?php echo $this->Js->writeBuffer(); // Write cached scripts ?>