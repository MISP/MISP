<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['org'] == $me['org']));
?>
<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Edit Attribute'); ?></legend>
<?php
echo $this->Form->input('id');
echo $this->Form->input('category', array('between' => $this->Html->div('forminfo', '', array('id' => 'AttributeCategoryDiv'))));
if ($attachment) {
	echo $this->Form->hidden('type', array('between' => $this->Html->div('forminfo', '', array('id' => 'AttributeTypeDiv'))));
	echo "<BR>Type: " . $this->Form->value('Attribute.type');
} else {
	echo $this->Form->input('type', array('between' => $this->Html->div('forminfo', '', array('id' => 'AttributeTypeDiv'))));
}
if ('true' == Configure::read('CyDefSIG.sync')) {
	if ('true' == Configure::read('CyDefSIG.private')) {
		echo $this->Form->input('distribution', array('label' => 'Distribution',
			'between' => $this->Html->div('forminfo', '', array('id' => 'AttributeDistributionDiv'))
		));
	} else {
		echo $this->Form->input('private', array(
				'before' => $this->Html->div('forminfo', isset($attrDescriptions['private']['formdesc']) ? $attrDescriptions['private']['formdesc'] : $attrDescriptions['private']['desc']),
		));
	}
}
echo $this->Form->input('to_ids', array(
			'before' => $this->Html->div('forminfo', isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc']),
			'label' => 'IDS Signature?'
));
if ($attachment) {
	echo $this->Form->hidden('value');
	echo "<BR>Value: " . $this->Form->value('Attribute.value');
} else {
	echo $this->Form->input('value', array(
			'type' => 'textarea',
			'error' => array('escape' => false),
	));
}
$this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("#AttributeCategory")');
$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
$this->Js->get('#AttributeDistribution')->event('change', 'showFormInfo("#AttributeDistribution")');

?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<li><?php
		$attribute = ClassRegistry::init('Attribute')->findById($this->Form->value('Attribute.id'));	// TODO ACL $attribute??
		if ($mayModify) echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $this->Form->value('Attribute.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Attribute.id'))); ?></li>
		<li>&nbsp;</li>
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
// fix the select box based on what was selected
var type_value = $('#AttributeType').val();
formCategoryChanged("#AttributeCategory");
$('#AttributeType').val(type_value);

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
