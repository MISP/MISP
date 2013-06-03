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
			echo $this->Form->input('distribution', array('label' => 'Distribution', 'selected' => $maxDist,
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
				'after' => $this->Html->div('forminfo', 'Tick this box to neutralize the sample. Every malware sample will be zipped with the password "infected"', ''),
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
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('View Event', array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id'])); ?> </li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><?php echo $this->Html->link('Edit Event', array('controller' => 'events', 'action' => 'edit', $this->request->data['Attribute']['event_id'])); ?> </li>
		<li><?php echo $this->Form->postLink('Delete Event', array('controller' => 'events', 'action' => 'delete', $this->request->data['Attribute']['event_id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Attribute']['event_id'])); ?></li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $this->request->data['Attribute']['event_id']));?> </li>
		<li class="active"><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $this->request->data['Attribute']['event_id']));?> </li>
		<li><?php echo $this->Html->link('Populate event from IOC', array('controller' => 'events', 'action' => 'addIOC', $this->request->data['Attribute']['event_id']));?> </li>
		<?php else:	?>
		<li><?php echo $this->Html->link('Propose Attribute', array('controller' => 'shadow_attributes', 'action' => 'add', $this->request->data['Attribute']['event_id']));?> </li>
		<li><?php echo $this->Html->link('Propose Attachment', array('controller' => 'shadow_attributes', 'action' => 'add_attachment', $this->request->data['Attribute']['event_id']));?> </li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link(__('Contact reporter', true), array('controller' => 'events', 'action' => 'contact', $this->request->data['Attribute']['event_id'])); ?> </li>
		<li><?php echo $this->Html->link(__('Download as XML', true), array('controller' => 'events', 'action' => 'xml', 'download', $this->request->data['Attribute']['event_id'])); ?></li>
		<li><?php echo $this->Html->link(__('Download as IOC', true), array('controller' => 'events', 'action' => 'downloadOpenIOCEvent', $this->request->data['Attribute']['event_id'])); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
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