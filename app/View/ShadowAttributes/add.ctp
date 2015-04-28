<div class="shadow_attributes <?php if (!$ajax) echo 'form';?>">
<?php echo $this->Form->create('ShadowAttribute', array('url' => '/shadow_attributes/add/' . $event_id));?>
	<fieldset>
	<legend><?php echo __('Add Proposal'); ?></legend>
	<div id="formWarning" class="message ajaxMessage"></div>
	<div class="add_attribute_fields">
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
			echo $this->Form->input('comment', array(
					'type' => 'text',
					'label' => 'Contextual Comment',
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'input-xxlarge'
			));
			?>
			<div class="input clear"></div>
			<?php
			echo $this->Form->input('to_ids', array(
					'checked' => true,
					'label' => 'for Intrusion Detection System',
			));
			echo $this->Form->input('batch_import', array(
					'type' => 'checkbox',
			));
			// link an onchange event to the form elements
			$this->Js->get('#ShadowAttributeCategory')->event('change', 'formCategoryChanged("#ShadowAttributeCategory")');
			$this->Js->get('#ShadowAttributeType')->event('change', 'showFormInfo("#ShadowAttributeType")');
		?>
	</div>
	</fieldset>
	<p style="color:red;font-weight:bold;display:none;" id="warning-message">Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
	<?php if ($ajax): ?>
		<div class="overlay_spacing">
			<table>
				<tr>
				<td style="vertical-align:top">
					<span id="submitButton" class="btn btn-primary" onClick="submitPopoverForm('<?php echo $event_id;?>', 'propose')">Propose</span>
				</td>
				<td style="width:540px;">
					<p style="color:red;font-weight:bold;display:none;<?php if($ajax) echo "text-align:center;"?>" id="warning-message">Warning: You are about to share data that is of a sensitive nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
				</td>
				<td style="vertical-align:top;">
					<span class="btn btn-inverse" id="cancel_attribute_add">Cancel</span>
				</td>
				</tr>
			</table>
		</div>
	<?php 
		else: 
			echo $this->Form->button('Propose', array('class' => 'btn btn-primary'));
		endif;
		echo $this->Form->end();
	?>
</div>
<?php 
	$event['Event']['id'] = $this->request->data['ShadowAttribute']['event_id'];
	if (!$ajax) {
		echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'proposeAttribute', 'event' => $event));
	}
?>
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
	
	$("#ShadowAttributeType, #ShadowAttributeCategory, #ShadowAttribute").on('mouseover', function(e) {
	    var $e = $(e.target);
	    if ($e.is('option')) {
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'focus',
	            placement: 'right',
	            content: formInfoValues[$e.val()],
	        }).popover('show');
	    }
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#ShadowAttributeType, #ShadowAttributeCategory, #ShadowAttribute").on('change', function(e) {
		if (this.id === "ShadowAttributeCategory") {
			var select = document.getElementById("ShadowAttributeCategory");
			if (select.value === 'Attribution' || select.value === 'Targeting data') {
				$("#warning-message").show();
			} else {
				$("#warning-message").hide();
			}
		}
	    var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'focus',
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

<?php if ($ajax): ?>
$('#cancel_attribute_add').click(function() {
	$('#gray_out').fadeOut();
	$('#popover_form').fadeOut();
});	

<?php endif; ?>
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
