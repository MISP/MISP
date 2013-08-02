<div class="shadow_attributes form">
<?php echo $this->Form->create('ShadowAttribute');?>
	<fieldset>
		<legend><?php echo __('Add ShadowAttribute'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category', array(
				'empty' => '(choose one)',
				'div' => 'input'
				));
		echo $this->Form->input('type', array(
				'empty' => '(first choose category)'
				));
		?>
		<div class="input clear"></div>
		<?php
		echo $this->Form->input('value', array(
				'type' => 'textarea',
				'error' => array('escape' => false),
				'class' => 'input-xxlarge clear'
		));
		?>
		<div class="input clear"></div>
		<?php
		echo $this->Form->input('batch_import', array(
				'type' => 'checkbox',
		));
		echo $this->Form->input('to_ids', array(
				'checked' => true,
				'label' => 'IDS Signature?',
		));
		// link an onchange event to the form elements
		$this->Js->get('#ShadowAttributeCategory')->event('change', 'formCategoryChanged("#ShadowAttributeCategory")');
		$this->Js->get('#ShadowAttributeType')->event('change', 'showFormInfo("#ShadowAttributeType")');
	?>
	</fieldset>
<?php
	echo $this->Form->button('Propose', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('View Event', array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id'])); ?> </li>
		<li class="active"><?php echo $this->Html->link('Propose Attribute', array('controller' => 'shadow_attributes', 'action' => 'add', $this->request->data['ShadowAttribute']['event_id']));?> </li>
		<li><?php echo $this->Html->link('Propose Attachment', array('controller' => 'shadow_attributes', 'action' => 'add_attachment', $this->request->data['ShadowAttribute']['event_id']));?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Contact reporter', array('controller' => 'events', 'action' => 'contact', $this->request->data['ShadowAttribute']['event_id'])); ?> </li>
		<li><?php echo $this->Html->link('Download as XML', array('controller' => 'events', 'action' => 'xml', 'download', $this->request->data['ShadowAttribute']['event_id'])); ?></li>
		<li><?php echo $this->Html->link('Download as IOC', array('controller' => 'events', 'action' => 'downloadOpenIOCEvent', $this->request->data['ShadowAttribute']['event_id'])); ?> </li>
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
	var options = $('#ShadowAttributeType').prop('options');
	$('option', $('#ShadowAttributeType')).remove();
	$.each(category_type_mapping[$('#ShadowAttributeCategory').val()], function(val, text) {
		options[options.length] = new Option(text, val);
	});
	// enable the form element
	$('#ShadowAttributeType').prop('disabled', false);
}

$(document).ready(function() {

	$("#ShadowAttributeType, #ShadowAttributeCategory, #ShadowAttribute, #ShadowAttributeDistribution").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});

	$("#ShadowAttributeType, #ShadowAttributeCategory, #ShadowAttribute, #ShadowAttributeDistribution").on('mouseover', function(e) {
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
            trigger: 'manual',
            placement: 'right',
        }).popover('show');
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#ShadowAttributeType, #ShadowAttributeCategory, #ShadowAttribute, #ShadowAttributeDistribution").on('change', function(e) {
	    var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'manual',
            placement: 'right',
            content: formInfoValues[$e.val()],
        }).popover('show');
	});

});

//
// Generate tooltip information
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
?>

function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();    // get the selected value
	$(idDiv).html(formInfoValues[value]);    // search in a lookup table

	// show it again
	$(idDiv).fadeIn('slow');
}

// hide the formInfo things
$('#ShadowAttributeTypeDiv').hide();
$('#ShadowAttributeCategoryDiv').hide();
$('#ShadowAttributeType').prop('disabled', true);


</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts