<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("AttributeMalware").removeAttribute("disabled");'));?>
	<fieldset>
		<legend><?php echo __('Add Attachment'); ?></legend>
		<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category');
		?>
		<div class="input clear"></div>
		<?php
		if ('true' == Configure::read('MISP.sync')) {
			$initialDistribution = 3;
			if (Configure::read('MISP.default_attribute_distribution') != null) {
				if (Configure::read('MISP.default_attribute_distribution') === 'event') {
					$initialDistribution = $currentDist;	
				} else {
					$initialDistribution = Configure::read('MISP.default_attribute_distribution');
				}
			}
			echo $this->Form->input('distribution', array(
					'options' => $distributionLevels,
					'label' => 'Distribution',
					'selected' => $initialDistribution,
			));
			echo $this->Form->input('comment', array(
					'type' => 'text',
					'label' => 'Contextual Comment',
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'input-xxlarge'
			));
			//'before' => $this->Html->div('forminfo', isset($attrDescriptions['distribution']['formdesc']) ? $attrDescriptions['distribution']['formdesc'] : $attrDescriptions['distribution']['desc']),));
		}
		?>
		<div class="input clear"></div>
		<div class="input">
		<?php
		echo $this->Form->file('value', array(
			'error' => array('escape' => false),
		));
		?>
		</div>
		<?php
		echo $this->Form->input('malware', array(
				'type' => 'checkbox',
				'checked' => false,
				// 'after' => $this->Html->div('forminfo', 'Tick this box to neutralize the sample. Every malware sample will be zipped with the password "infected"', ''),
				//'after' => '<br>Tick this box to neutralize the sample. Every malware sample will be zipped with the password "infected"',
		));
		// link an onchange event to the form elements
		$this->Js->get('#AttributeCategory')->event('change', 'malwareCheckboxSetter("#AttributeCategory")');
		?>
	</fieldset>
<?php
echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php 
	$event['Event']['id'] = $this->request->data['Attribute']['event_id'];
	$event['Event']['published'] = $published;
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addAttachment', 'event' => $event));
?>
<script type="text/javascript">
var formInfoValues = new Array();
<?php
foreach ($categoryDefinitions as $category => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['$category'] = \"$info\";\n";
}
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
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
$(document).ready(function() {
	
	$("#AttributeCategory, #AttributeDistribution").on('mouseover', function(e) {
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
	
	$("input, label").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});
	
	$("input, label").on('mouseover', function(e) {
		var $e = $(e.target);
		$('#'+e.currentTarget.id).popover('destroy');
	    $('#'+e.currentTarget.id).popover({
	        trigger: 'focus',
	        placement: 'right',
	    }).popover('show');
	});
	
	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#AttributeCategory, #AttributeDistribution").on('change', function(e) {
	    var $e = $(e.target);
	    $('#'+e.currentTarget.id).popover('destroy');
	    $('#'+e.currentTarget.id).popover({
	        trigger: 'focus',
	        placement: 'right',
	        content: formInfoValues[$e.val()],
	    }).popover('show');
	});
});
	
function malwareCheckboxSetter(id) {
idDiv = id+'Div';
var value = $(id).val();  // get the selected value

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
$(function(){
	// do checkbox un/ticked when the document is ready
	malwareCheckboxSetter("#AttributeCategory");
	}
);

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts