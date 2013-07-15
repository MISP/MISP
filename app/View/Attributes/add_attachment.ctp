<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("AttributeMalware").removeAttribute("disabled");'));?>
	<fieldset>
		<legend><?php echo __('Add Attachment'); ?></legend>
		<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category', array(
				'after' => $this->Html->div('forminfo', '', array('id' => 'AttributeCategoryDiv')),
				));
		if ('true' == Configure::read('CyDefSIG.sync')) {
			echo $this->Form->input('distribution', array(
					'options' => $distributionLevels,
					'label' => 'Distribution',
					'selected' => $currentDist,
					'after' => $this->Html->div('forminfo', '', array('id' => 'AttributeDistributionDiv')),
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
		$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
		$this->Js->get('#AttributeCategory')->event('change', 'showFormInfo("#AttributeCategory")');
		$this->Js->get('#AttributeDistribution')->event('change', 'showFormInfo("#AttributeDistribution")');
		?>
	</fieldset>
<?php
echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions  <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><a href="/events/view/<?php echo $this->request->data['Attribute']['event_id']; ?>">View Event</a></li>
		<li><a href="/logs/event_index/<?php echo $this->request->data['Attribute']['event_id'];?>">View Event History</a></li>
		<li><a href="/events/edit/<?php echo $this->request->data['Attribute']['event_id']; ?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('controller' => 'events', 'action' => 'delete', $this->request->data['Attribute']['event_id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Attribute']['event_id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $this->request->data['Attribute']['event_id']; ?>">Add Attribute</a></li>
		<li class="active"><a href="/attributes/add_attachment/<?php echo $this->request->data['Attribute']['event_id']; ?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $this->request->data['Attribute']['event_id']; ?>">Populate from IOC</a></li>
		<li><a href="/attributes/add_threatconnect/<?php echo $this->request->data['Attribute']['event_id']; ?>">Populate from ThreatConnect</a></li>
		<li class="divider"></li>
		<li><a href="/events/contact/<?php echo $this->request->data['Attribute']['event_id']; ?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $this->request->data['Attribute']['event_id']; ?>">Download as XML</a></li>
		<?php if ($published): ?>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $this->request->data['Attribute']['event_id'];?>">Download as IOC</a></li>
		<li><a href="/events/csv/download/<?php echo $this->request->data['Attribute']['event_id'];?>">Download as CSV</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>
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

//hide the formInfo things
$('#AttributeDistributionDiv').hide();
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts