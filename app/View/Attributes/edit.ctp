<?php
$mayModify = (($isAclModify && $attribute['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $attribute['Event']['org'] == $me['org']));
?>
<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Edit Attribute'); ?></legend>
		<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category', array(
				'after' => $this->Html->div('forminfo', '', array('id' => 'AttributeCategoryDiv')),
				'empty' => '(choose one)'
				));
		echo $this->Form->input('type', array(
				'after' => $this->Html->div('forminfo', '', array('id' => 'AttributeTypeDiv')),
				'empty' => '(first choose category)'
				));
		if ('true' == Configure::read('CyDefSIG.sync')) {
			echo $this->Form->input('distribution', array(
				'label' => 'Distribution',
				'selected' => $maxDist,
				'after' => $this->Html->div('forminfo', '', array('id' => 'AttributeDistributionDiv'))
			));
		}
		echo $this->Form->input('value', array(
				'type' => 'textarea',
				'error' => array('escape' => false),
				'div' => 'input clear',
				'class' => 'input-xxlarge'
		));
		?>
		<div class="input clear"></div>
		<?php
		echo $this->Form->input('to_ids', array(
					'checked' => true,
					'after' => $this->Html->div('forminfo', isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc']),
					'label' => 'IDS Signature?',
		));
		echo $this->Form->input('batch_import', array(
				'type' => 'checkbox',
				'after' => $this->Html->div('forminfo', 'Create multiple attributes one per line'),
		));

		// link an onchange event to the form elements
		$this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("#AttributeCategory")');
		$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
		$this->Js->get('#AttributeDistribution')->event('change', 'showFormInfo("#AttributeDistribution")');
		?>
	</fieldset>
<?php
echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
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
		<li class="active"><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $this->request->data['Attribute']['event_id']));?> </li>
		<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $this->request->data['Attribute']['event_id']));?> </li>
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
	var options = $('#AttributeType').prop('options');
	$('option', $('#AttributeType')).remove();
	$.each(category_type_mapping[$('#AttributeCategory').val()], function(val, text) {
		options[options.length] = new Option(text, val);
	});
	// enable the form element
	$('#AttributeType').prop('disabled', false);
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
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
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
$('#AttributeTypeDiv').hide();
$('#AttributeCategoryDiv').hide();
$('#AttributeDistributionDiv').hide();
// fix the select box based on what was selected
var type_value = $('#AttributeType').val();
formCategoryChanged("#AttributeCategory");
$('#AttributeType').val(type_value);

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
